use bech32::{u5, Variant}; // ✅ 移除未用的 FromBase32
use clap::Parser;
use glob::glob;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Opts {
    #[arg(long, default_value = "*.txt")]
    inputs: String,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    workers: Option<usize>,
    #[arg(long, default_value = "hash160")]
    out_prefix: String,
    #[arg(long)]
    b58_no_check: bool,
    #[arg(long, default_value_t = 1024 * 1024)]
    bufsize: usize,
}

#[derive(Clone, Copy)]
enum AddrType {
    P2PKH,
    P2SH,
    P2WPKH,
}

fn base58check_decode(addr: &str, check: bool) -> Option<Vec<u8>> {
    let bs = base58::FromBase58::from_base58(addr).ok()?;
    if bs.is_empty() {
        return None;
    }
    if !check {
        return Some(bs);
    }
    if bs.len() < 4 {
        return None;
    }
    let (data, chk) = bs.split_at(bs.len() - 4);
    let h = Sha256::digest(Sha256::digest(data)).to_vec();
    if h[0..4] != chk[..] {
        return None;
    }
    Some(data.to_vec()) // data = ver(1)+payload(20)
}

// === convertbits：修复 u5 -> u8 -> u32 ===
fn convertbits(data: &[u5], frombits: u32, tobits: u32) -> Option<Vec<u8>> {
    // 严格模式：不 pad
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << tobits) - 1;
    let mut ret: Vec<u8> = Vec::new();
    for v in data {
        let v_u32 = v.to_u8() as u32; // ✅ 修复：u5 -> u8 -> u32
        if v_u32 >> frombits != 0 {
            return None;
        }
        acc = (acc << frombits) | v_u32;
        bits += frombits;
        while bits >= tobits {
            bits -= tobits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if bits != 0 {
        return None;
    }
    Some(ret)
}

fn addr_to_hash160(token: &str, b58_check: bool) -> Option<(AddrType, String)> {
    if token.is_empty() {
        return None;
    }
    let first = token.as_bytes()[0];
    if first == b'1' || first == b'3' {
        let bs = base58check_decode(token, b58_check)?;
        let (ver, payload) = if b58_check {
            if bs.len() != 21 {
                return None;
            }
            (bs[0], &bs[1..])
        } else {
            if bs.len() < 21 {
                return None;
            }
            (bs[bs.len() - 21], &bs[bs.len() - 20..])
        };
        if payload.len() != 20 {
            return None;
        }
        return match ver {
            0x00 => Some((AddrType::P2PKH, hex::encode(payload))), // ✅ 依赖 hex
            0x05 => Some((AddrType::P2SH, hex::encode(payload))),
            _ => None,
        };
    }

    if token.len() >= 3 && (&token[0..3]).eq_ignore_ascii_case("bc1") {
        let (hrp, data, variant) = bech32::decode(token).ok()?;
        if variant != Variant::Bech32 {
            return None;
        }
        if data.is_empty() {
            return None;
        }
        let witver = data[0].to_u8();
        let prog = convertbits(&data[1..], 5, 8)?;
        if witver == 0 && prog.len() == 20 {
            return Some((AddrType::P2WPKH, hex::encode(prog))); // ✅ 依赖 hex
        }
        return None;
    }

    None
}

fn process_reader<R: Read>(
    mut rdr: R,
    out_p2pkh: &mut dyn Write,
    out_p2sh: &mut dyn Write,
    out_p2wpkh: &mut dyn Write,
    b58_check: bool,
) -> io::Result<(u64, u64, u64, u64)> {
    let mut buf = String::new();
    let mut reader = BufReader::new(&mut rdr);
    let mut c1 = 0u64;
    let mut c2 = 0u64;
    let mut c3 = 0u64;
    let mut skip = 0u64;

    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        for tok in buf.split_whitespace() {
            let b = tok.as_bytes();
            if b.is_empty() {
                continue;
            }
            let c0 = b[0];
            if !(c0 == b'1' || c0 == b'3' || c0 == b'b' || c0 == b'B') {
                continue;
            }
            match addr_to_hash160(tok, b58_check) {
                Some((AddrType::P2PKH, h)) => {
                    writeln!(out_p2pkh, "{}", h)?;
                    c1 += 1;
                }
                Some((AddrType::P2SH, h)) => {
                    writeln!(out_p2sh, "{}", h)?;
                    c2 += 1;
                }
                Some((AddrType::P2WPKH, h)) => {
                    writeln!(out_p2wpkh, "{}", h)?;
                    c3 += 1;
                }
                None => {
                    skip += 1;
                }
            }
        }
    }
    Ok((c1, c2, c3, skip))
}

fn process_file(path: &Path, tmpdir: &Path, b58_check: bool) -> io::Result<(String, u64, u64, u64, u64, PathBuf, PathBuf, PathBuf)> {
    let base = path.file_name().unwrap().to_string_lossy().to_string();
    let p1 = tmpdir.join(format!("{base}.p2pkh.tmp"));
    let p2 = tmpdir.join(format!("{base}.p2sh.tmp"));
    let p3 = tmpdir.join(format!("{base}.p2wpkh.tmp"));

    let mut o1 = BufWriter::new(File::create(&p1)?);
    let mut o2 = BufWriter::new(File::create(&p2)?);
    let mut o3 = BufWriter::new(File::create(&p3)?);

    let f = File::open(path)?;
    let (c1, c2, c3, skip) = process_reader(f, &mut o1, &mut o2, &mut o3, b58_check)?;
    o1.flush()?; o2.flush()?; o3.flush()?;
    Ok((base, c1, c2, c3, skip, p1, p2, p3))
}

fn try_sort_unique(inputs: &[PathBuf], out: &Path) -> io::Result<Option<u64>> {
    let has_sort = Command::new("bash")
        .arg("-lc")
        .arg("command -v sort >/dev/null 2>&1")
        .status()
        .ok()
        .map(|s| s.success())
        .unwrap_or(false);

    if !has_sort {
        let mut outw = BufWriter::new(File::create(out)?);
        for p in inputs {
            let mut f = File::open(p)?;
            io::copy(&mut f, &mut outw)?;
        }
        outw.flush()?;
        return Ok(None);
    }

    // ✅ 使用 shell-escape 安全拼接路径
    let list = inputs
        .iter()
        .map(|p| shell_escape::escape(p.display().to_string().into()))
        .collect::<Vec<_>>()
        .join(" ");
    let out_esc = shell_escape::escape(out.display().to_string().into());
    let cmd = format!("cat {list} | LC_ALL=C sort -u > {out_esc}");
    let status = Command::new("bash").arg("-lc").arg(&cmd).status()?;
    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "sort -u failed"));
    }
    let count = BufReader::new(File::open(out)?).lines().count() as u64;
    Ok(Some(count))
}

fn main() -> io::Result<()> {
    let opts = Opts::parse();

    if let Some(n) = opts.workers {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .ok();
    }

    let tmpdir = PathBuf::from("_tmp_hash160");
    fs::create_dir_all(&tmpdir)?;

    let out_p2pkh = PathBuf::from(format!("{}_p2pkh.txt", opts.out_prefix));
    let out_p2sh = PathBuf::from(format!("{}_p2sh.txt", opts.out_prefix));
    let out_p2wpkh = PathBuf::from(format!("{}_p2wpkh.txt", opts.out_prefix));

    let mut temp_p2pkh: Vec<PathBuf> = vec![];
    let mut temp_p2sh: Vec<PathBuf> = vec![];
    let mut temp_p2wpkh: Vec<PathBuf> = vec![];

    let total = Mutex::new((0u64, 0u64, 0u64, 0u64));

    if opts.stdin {
        let base = "STDIN".to_string();
        let p1 = tmpdir.join("STDIN.p2pkh.tmp");
        let p2 = tmpdir.join("STDIN.p2sh.tmp");
        let p3 = tmpdir.join("STDIN.p2wpkh.tmp");
        let mut o1 = BufWriter::new(File::create(&p1)?);
        let mut o2 = BufWriter::new(File::create(&p2)?);
        let mut o3 = BufWriter::new(File::create(&p3)?);

        // 简单基于行的 stdin 处理（bufsize 可调）
        let mut stdin = io::stdin().lock();
        let mut buf = vec![0u8; opts.bufsize];
        let mut carry = Vec::<u8>::new();

        loop {
            let n = stdin.read(&mut buf)?;
            if n == 0 {
                if !carry.is_empty() {
                    let s = String::from_utf8_lossy(&carry);
                    process_reader(s.as_bytes(), &mut o1, &mut o2, &mut o3, !opts.b58_no_check)?;
                }
                break;
            }
            carry.extend_from_slice(&buf[..n]);
            let mut last = 0usize;
            for (i, b) in carry.iter().enumerate() {
                if *b == b'\n' {
                    let chunk = &carry[last..=i];
                    process_reader(chunk, &mut o1, &mut o2, &mut o3, !opts.b58_no_check)?;
                    last = i + 1;
                }
            }
            carry = carry.split_off(last);
        }

        o1.flush()?; o2.flush()?; o3.flush()?;
        let cnt = |p: &PathBuf| -> io::Result<u64> {
            Ok(BufReader::new(File::open(p)?).lines().count() as u64)
        };
        let c1 = cnt(&p1)?; let c2 = cnt(&p2)?; let c3 = cnt(&p3)?; let skip = 0;
        println!("[+] {base}  p2pkh={c1} p2sh={c2} p2wpkh={c3} skip={skip}");
        temp_p2pkh.push(p1);
        temp_p2sh.push(p2);
        temp_p2wpkh.push(p3);
        *total.lock().unwrap() = (c1, c2, c3, skip);
    } else {
        // ✅ rayon 并行阶段先收集结果，避免在 Fn 闭包里直接修改外部可变 Vec（修复 E0596）
        let mut files: Vec<PathBuf> = vec![];
        for pat in opts.inputs.split(',') {
            for entry in glob(pat.trim()).expect("invalid glob") {
                if let Ok(p) = entry {
                    files.push(p);
                }
            }
        }
        if files.is_empty() {
            eprintln!("No input files matched.");
            std::process::exit(1);
        }

        let results: Vec<_> = files.par_iter()
            .map(|p| process_file(p, &tmpdir, !opts.b58_no_check))
            .collect();

        for r in results {
            match r {
                Ok((base, c1, c2, c3, skip, p1, p2, p3)) => {
                    println!("[+] {base}  p2pkh={c1} p2sh={c2} p2wpkh={c3} skip={skip}");
                    {
                        let mut t = total.lock().unwrap();
                        t.0 += c1; t.1 += c2; t.2 += c3; t.3 += skip;
                    }
                    temp_p2pkh.push(p1);
                    temp_p2sh.push(p2);
                    temp_p2wpkh.push(p3);
                }
                Err(e) => eprintln!("[-] error: {}", e),
            }
        }
    }

    let n1 = try_sort_unique(&temp_p2pkh, &out_p2pkh)?;
    let n2 = try_sort_unique(&temp_p2sh, &out_p2sh)?;
    let n3 = try_sort_unique(&temp_p2wpkh, &out_p2wpkh)?;
    let (c1, c2, c3, skip) = *total.lock().unwrap();

    println!("\n[*] Done.");
    println!(
        "    p2pkh (unique): {} -> {}",
        n1.map(|x| x.to_string()).unwrap_or_else(|| "concat".into()),
        out_p2pkh.display()
    );
    println!(
        "    p2sh  (unique): {} -> {}",
        n2.map(|x| x.to_string()).unwrap_or_else(|| "concat".into()),
        out_p2sh.display()
    );
    println!(
        "    p2wpkh(unique): {} -> {}",
        n3.map(|x| x.to_string()).unwrap_or_else(|| "concat".into()),
        out_p2wpkh.display()
    );
    println!("    totals (raw): p2pkh={c1} p2sh={c2} p2wpkh={c3} skip={skip}");

    for p in temp_p2pkh.into_iter().chain(temp_p2sh).chain(temp_p2wpkh) {
        let _ = fs::remove_file(p);
    }
    let _ = fs::remove_dir("_tmp_hash160");

    Ok(())
}
