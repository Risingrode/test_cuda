use clap::Parser;
use glob::glob;
use rayon::prelude::*;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use bech32::{u5, Variant};
use base58::FromBase58;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(version, about = "Make sorted binary for -i/--in (rmd160 hashes or xpoints).")]
struct Opts {
    /// 输入文件通配，逗号分隔（如：'*.txt,parts/*.txt'）；配合 --stdin 可忽略
    #[arg(long, default_value = "*.txt")]
    inputs: String,
    /// 从标准输入读取（按行/空白分词）
    #[arg(long)]
    stdin: bool,
    /// 模式：hash160-from-addr | ripemd160-from-hex | xpoint-from-hex
    #[arg(long, default_value = "hash160-from-addr")]
    mode: String,
    /// 输出二进制文件路径（最终结果）。内容为已排序、去重、定长记录
    #[arg(long)]
    out: String,
    /// 每文件并行度（默认=CPU核数）
    #[arg(long)]
    workers: Option<usize>,
    /// 从 stdin 读时的块大小（字节）
    #[arg(long, default_value_t = 1024 * 1024)]
    bufsize: usize,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Hash160FromAddr,   // 20B
    Ripemd160FromHex,  // 20B
    XPointFromHex,     // 32B
}

impl Mode {
    fn from_str(s: &str) -> io::Result<Self> {
        match s {
            "hash160-from-addr" => Ok(Self::Hash160FromAddr),
            "ripemd160-from-hex" => Ok(Self::Ripemd160FromHex),
            "xpoint-from-hex" => Ok(Self::XPointFromHex),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mode must be one of: hash160-from-addr | ripemd160-from-hex | xpoint-from-hex",
            )),
        }
    }
    fn rec_len(&self) -> usize {
        match self {
            Mode::Hash160FromAddr => 20,
            Mode::Ripemd160FromHex => 20,
            Mode::XPointFromHex => 32,
        }
    }
}

/* ------------------ 地址解析（hash160） ------------------ */
fn base58check_decode(addr: &str) -> Option<Vec<u8>> {
    let bs = addr.from_base58().ok()?;
    if bs.len() < 4 {
        return None;
    }
    let (data, chk) = bs.split_at(bs.len() - 4);
    let h = Sha256::digest(Sha256::digest(data));
    if h[0..4] != chk[..] {
        return None;
    }
    Some(data.to_vec()) // data = ver(1)+payload(20)
}

fn convertbits(data: &[bech32::u5], frombits: u32, tobits: u32) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << tobits) - 1;
    let mut ret: Vec<u8> = Vec::new();
    for v in data {
        let v_u32 = v.to_u8() as u32;
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

/// 从比特币地址得到 20B payload（P2PKH/P2SH/P2WPKH）
fn addr_to_hash160_bytes(addr: &str) -> Option<[u8; 20]> {
    let b = addr.as_bytes();
    if b.is_empty() {
        return None;
    }
    // Base58: 1/3 开头
    if b[0] == b'1' || b[0] == b'3' {
        let data = base58check_decode(addr)?;
        if data.len() != 21 {
            return None;
        }
        let ver = data[0];
        let payload = &data[1..];
        if payload.len() != 20 {
            return None;
        }
        match ver {
            0x00 | 0x05 => {
                let mut out = [0u8; 20];
                out.copy_from_slice(payload);
                return Some(out);
            }
            _ => return None,
        }
    }
    // Bech32: bc1...
    if addr.len() >= 3 && (&addr[0..3]).eq_ignore_ascii_case("bc1") {
        let (_hrp, data, variant) = bech32::decode(addr).ok()?;
        if variant != Variant::Bech32 || data.is_empty() {
            return None;
        }
        let witver = data[0].to_u8();
        let prog = convertbits(&data[1..], 5, 8)?;
        if witver == 0 && prog.len() == 20 {
            let mut out = [0u8; 20];
            out.copy_from_slice(&prog);
            return Some(out);
        }
    }
    None
}

/* ------------------ HEX 输入：RIPEMD160 / XPoint ------------------ */

fn ripemd160_of_hex(s: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(s).ok()?;
    use ripemd::Digest;
    let mut h = Ripemd160::new();
    h.update(&bytes);
    let out = h.finalize();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    Some(arr)
}

/// 从公钥 hex 获取 x 坐标（32B）
fn xpoint_of_pubkey_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    match bytes.first().copied() {
        Some(0x02) | Some(0x03) => {
            if bytes.len() != 33 {
                return None;
            }
            let mut x = [0u8; 32];
            x.copy_from_slice(&bytes[1..33]);
            Some(x)
        }
        Some(0x04) => {
            if bytes.len() != 65 {
                return None;
            }
            let mut x = [0u8; 32];
            x.copy_from_slice(&bytes[1..33]); // 0x04 + X(32) + Y(32)
            Some(x)
        }
        _ => None,
    }
}

/* ------------------ 输入读取 ------------------ */

fn read_tokens_from_file(path: &Path) -> io::Result<Vec<String>> {
    let f = File::open(path)?;
    let mut rdr = BufReader::new(f);
    let mut buf = String::new();
    let mut out = Vec::new();
    loop {
        buf.clear();
        let n = rdr.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        for tok in buf.split_whitespace() {
            if !tok.is_empty() {
                out.push(tok.to_string());
            }
        }
    }
    Ok(out)
}

fn read_tokens_from_stdin(bufsize: usize) -> io::Result<Vec<String>> {
    let mut stdin = io::stdin().lock();
    let mut buf = vec![0u8; bufsize];
    let mut carry = Vec::<u8>::new();
    let mut out = Vec::new();

    loop {
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            if !carry.is_empty() {
                let s = String::from_utf8_lossy(&carry);
                out.extend(s.split_whitespace().map(|x| x.to_string()));
            }
            break;
        }
        carry.extend_from_slice(&buf[..n]);
        let mut last = 0usize;
        for (i, b) in carry.iter().enumerate() {
            if *b == b'\n' {
                let chunk = &carry[last..=i];
                let s = String::from_utf8_lossy(chunk);
                out.extend(s.split_whitespace().map(|x| x.to_string()));
                last = i + 1;
            }
        }
        carry = carry.split_off(last);
    }
    Ok(out)
}

/* ------------------ 单文件处理：产生已排序、去重的临时块 ------------------ */
fn process_one_file(path: Option<&Path>, mode: Mode, bufsize: usize) -> io::Result<PathBuf> {
    let tokens = if let Some(p) = path {
        read_tokens_from_file(p)?
    } else {
        read_tokens_from_stdin(bufsize)?
    };

    let rec_len = mode.rec_len();
    let mut recs: Vec<Vec<u8>> = Vec::with_capacity(tokens.len());

    for t in tokens {
        match mode {
            Mode::Hash160FromAddr => {
                if let Some(h) = addr_to_hash160_bytes(&t) {
                    recs.push(h.to_vec());
                }
            }
            Mode::Ripemd160FromHex => {
                if let Some(h) = ripemd160_of_hex(&t) {
                    recs.push(h.to_vec());
                }
            }
            Mode::XPointFromHex => {
                if let Some(x) = xpoint_of_pubkey_hex(&t) {
                    recs.push(x.to_vec());
                }
            }
        }
    }

    // 排序 + 去重（字节序）
    recs.sort_unstable();
    recs.dedup();

    // 写临时块
    let tmpdir = PathBuf::from("_tmp_mkbin");
    fs::create_dir_all(&tmpdir)?;
    let name = match path {
        Some(p) => format!(
            "{}.{}.bin",
            p.file_name().unwrap().to_string_lossy(),
            rec_len
        ),
        None => "STDIN.bin".to_string(),
    };
    let outp = tmpdir.join(name);
    let mut w = BufWriter::new(File::create(&outp)?);
    for r in recs {
        w.write_all(&r)?;
    }
    w.flush()?;
    Ok(outp)
}

/* ------------------ k 路归并（二进制块） ------------------ */

#[derive(Eq)]
struct HeapItem {
    key: Vec<u8>,
    idx: usize, // 来自哪个输入
}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap 是最大堆，我们需要最小堆 => 反向
        other.key.cmp(&self.key)
    }
}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

fn kway_merge_sorted_bins(inputs: &[PathBuf], rec_len: usize, out: &Path) -> io::Result<()> {
    let mut readers: Vec<BufReader<File>> = Vec::new();
    for p in inputs {
        readers.push(BufReader::new(File::open(p)?));
    }
    let mut heap: BinaryHeap<HeapItem> = BinaryHeap::new();
    let mut buffers: Vec<Vec<u8>> = vec![vec![0u8; rec_len]; readers.len()];

    // 先从每个块读一条
    for (i, rdr) in readers.iter_mut().enumerate() {
        let buf = &mut buffers[i];
        if rdr.read_exact(buf).is_ok() {
            heap.push(HeapItem {
                key: buf.clone(),
                idx: i,
            });
        }
    }

    let mut w = BufWriter::new(File::create(out)?);
    let mut prev: Option<Vec<u8>> = None;

    while let Some(item) = heap.pop() {
        // 去重：只写与上一条不同的记录
        if prev.as_ref().map_or(true, |p| p != &item.key) {
            w.write_all(&item.key)?;
            prev = Some(item.key.clone());
        }
        // 从对应 reader 再读一条
        let i = item.idx;
        let buf = &mut buffers[i];
        if readers[i].read_exact(buf).is_ok() {
            heap.push(HeapItem {
                key: buf.clone(),
                idx: i,
            });
        }
    }
    w.flush()?;
    Ok(())
}

/* ------------------ 主流程 ------------------ */

fn main() -> io::Result<()> {
    let opts = Opts::parse();
    if let Some(n) = opts.workers {
        rayon::ThreadPoolBuilder::new().num_threads(n).build_global().ok();
    }

    let mode = Mode::from_str(&opts.mode)?;
    let rec_len = mode.rec_len();

    // 1) 先生成每个输入的“已排序、去重”临时块
    let mut chunks: Vec<PathBuf> = Vec::new();

    if opts.stdin {
        // 单路 stdin
        let p = process_one_file(None, mode, opts.bufsize)?;
        chunks.push(p);
    } else {
        // 以文件并行
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

        let results: Vec<_> = files
            .par_iter()
            .map(|p| process_one_file(Some(p), mode, opts.bufsize))
            .collect();

        for r in results {
            match r {
                Ok(pb) => chunks.push(pb),
                Err(e) => eprintln!("[-] process error: {e}"),
            }
        }
    }

    // 2) k 路归并 -> 输出最终“二进制 + 已排序 + 去重”文件
    let outp = PathBuf::from(&opts.out);
    kway_merge_sorted_bins(&chunks, rec_len, &outp)?;

    // 3) 清理
    for c in chunks {
        let _ = fs::remove_file(c);
    }
    let _ = fs::remove_dir("_tmp_mkbin");

    eprintln!(
        "OK -> {} (records: {} bytes each, sorted & unique)",
        outp.display(),
        rec_len
    );
    Ok(())
}
