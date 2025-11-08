#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
超大文本/压缩数据 → 提取比特币地址为 hash160（P2PKH / P2SH / P2WPKH）。
优化点：
- 多进程：每文件一个进程
- 块读取：减少 Python 逐行迭代成本
- 无正则：前缀快速过滤
- 查表：Base58/Bech32 字符映射 array 查表
- 外部 sort -u 合并去重
用法示例：
  python3 extract_hash160_fast.py --inputs "*.txt" --workers 6
  pigz -dc *.gz | python3 extract_hash160_fast.py --stdin --workers 6
选项：
  --b58-no-check   跳过 Base58Check（更快，略降安全）
"""

import argparse, glob, io, os, sys, subprocess
from multiprocessing import Pool
from array import array

# ============== Base58 查表与解码（可选校验） ==============
_B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = array('i', [-1]*128)
for i, c in enumerate(_B58_ALPH):
    _B58_MAP[ord(c)] = i

def b58decode(addr: str, check=True):
    n = 0
    for ch in addr:
        oc = ord(ch)
        if oc >= 128: return None
        v = _B58_MAP[oc]
        if v < 0: return None
        n = n*58 + v
    # big-endian bytes
    bs = n.to_bytes((n.bit_length()+7)//8, 'big') if n else b'\x00'
    # leading '1' => 0x00 padding
    pad = 0
    for ch in addr:
        if ch == '1': pad += 1
        else: break
    bs = b'\x00'*pad + bs
    if len(bs) < 21:  # ver(1)+payload(20)+chk(4)? 这里不强制 chk
        return None
    if not check:
        return bs
    import hashlib
    if len(bs) < 4: return None
    data, chk = bs[:-4], bs[-4:]
    h = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    if chk != h: return None
    return data  # 带校验时返回 data= ver(1)+payload(20)

# ============== Bech32/BIP173（精简快路径） ==============
_B32_CHR = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_B32_MAP = array('i', [-1]*128)
for i, c in enumerate(_B32_CHR):
    _B32_MAP[ord(c)] = i

def _hrp_expand(hrp):
    return [ord(x)>>5 for x in hrp] + [0] + [ord(x)&31 for x in hrp]

def _polymod(vals):
    GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in vals:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b>>i)&1: chk ^= GEN[i]
    return chk

def bech32_decode(s: str):
    # 简化：只接受全小写/全大写
    if not s: return None, None
    if s.lower()!=s and s.upper()!=s: return None, None
    s = s.lower()
    p = s.rfind('1')
    if p < 1 or p+7 > len(s): return None, None
    hrp, data = s[:p], s[p+1:]
    vals = []
    for ch in data:
        oc = ord(ch)
        if oc >= 128: return None, None
        v = _B32_MAP[oc]
        if v < 0: return None, None
        vals.append(v)
    if _polymod(_hrp_expand(hrp)+vals) != 1: return None, None
    return hrp, vals[:-6]

def convertbits(data, frombits, tobits):
    acc = 0; bits = 0; out = []
    maxv = (1<<tobits)-1
    for v in data:
        if v<0 or (v>>frombits): return None
        acc = (acc<<frombits)|v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc>>bits)&maxv)
    if bits: return None   # 不 pad，严格解码
    return bytes(out)

# ============== 地址 → hash160 ==============
def addr_to_hash160(token: str, b58_check=True):
    t0 = token[0]
    if t0 == '1' or t0 == '3':
        bs = b58decode(token, check=b58_check)
        if not bs: return None, None
        if b58_check:
            if len(bs) != 21: return None, None
            ver, payload = bs[0], bs[1:]
        else:
            # 无校验模式：最后21字节视作 ver+payload（兼容极端输入）
            if len(bs) < 21: return None, None
            ver, payload = bs[-21], bs[-20:]
        if ver == 0x00:  # P2PKH
            return 'p2pkh', payload.hex()
        if ver == 0x05:  # P2SH
            return 'p2sh', payload.hex()
        return None, None
    # 快速判定 bech32
    if (t0=='b' or t0=='B') and token[:3].lower()=='bc1':
        hrp, data = bech32_decode(token)
        if not hrp or not data: return None, None
        witver = data[0]
        prog = convertbits(data[1:], 5, 8)
        if prog is None: return None, None
        # 仅返回 P2WPKH（20字节）
        if witver == 0 and len(prog)==20:
            return 'p2wpkh', prog.hex()
        return None, None
    return None, None

# ============== 读取器（块扫描，空白分词） ==============
def iter_tokens(path=None, bufsize=1024*1024):
    if path is None:
        f = sys.stdin.buffer
        close = False
    else:
        f = open(path, 'rb', buffering=bufsize)
        close = True
    try:
        rem = b''
        while True:
            chunk = f.read(bufsize)
            if not chunk:
                if rem:
                    for tok in rem.split():
                        yield tok.decode('utf-8', 'ignore')
                break
            data = rem + chunk
            # 以空白分割，最后一段可能不完整，留到下个块
            parts = data.split()
            if data[-1:].isspace():
                rem = b''
            else:
                rem = parts.pop().encode() if parts else data
                if parts:  # 如果只有一个不完整 token，parts 可能为空
                    pass
            for p in parts:
                yield p.decode('utf-8', 'ignore')
    finally:
        if close: f.close()

# ============== 单文件处理 ==============
def process_file(path, outdir, b58_check):
    base = os.path.basename(path) if path else "STDIN"
    p1 = os.path.join(outdir, f"{base}.p2pkh.tmp")
    p2 = os.path.join(outdir, f"{base}.p2sh.tmp")
    p3 = os.path.join(outdir, f"{base}.p2wpkh.tmp")
    c1=c2=c3=cx=0

    with open(p1,'w') as o1, open(p2,'w') as o2, open(p3,'w') as o3:
        for tok in iter_tokens(None if path is None else path):
            if not tok: continue
            # 快速前缀过滤：只看 1/3/bc1 开头的 token
            ch = tok[0]
            if ch not in ('1','3','b','B'): 
                continue
            typ, h160 = addr_to_hash160(tok, b58_check=b58_check)
            if not h160:
                cx += 1
                continue
            if typ=='p2pkh': o1.write(h160+'\n'); c1+=1
            elif typ=='p2sh': o2.write(h160+'\n'); c2+=1
            elif typ=='p2wpkh': o3.write(h160+'\n'); c3+=1
    return (path or "STDIN", c1,c2,c3,cx, p1,p2,p3)

def sort_unique(temp_files, out_path):
    temp_files = [p for p in temp_files if os.path.exists(p)]
    if not temp_files:
        open(out_path,'w').close()
        return 0
    try:
        cmd = ["bash","-lc", f"cat {' '.join(map(repr, temp_files))} | LC_ALL=C sort -u > {repr(out_path)}"]
        subprocess.check_call(cmd)
        # 统计行数
        with open(out_path,'r') as f:
            return sum(1 for _ in f)
    except Exception:
        # 退化：Python 去重
        seen=set(); n=0
        with open(out_path,'w') as out:
            for p in temp_files:
                with open(p,'r') as f:
                    for line in f:
                        s=line.strip()
                        if s and s not in seen:
                            seen.add(s); out.write(s+'\n'); n+=1
        return n

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", default="*.txt", help="输入文件通配，逗号分隔；配合 --stdin 可忽略此项")
    ap.add_argument("--stdin", action="store_true", help="从标准输入读取（支持 pigz -dc *.gz | ...）")
    ap.add_argument("--workers", type=int, default=max(1,(os.cpu_count() or 4)//2))
    ap.add_argument("--out-prefix", default="hash160")
    ap.add_argument("--b58-no-check", action="store_true", help="跳过 Base58Check 校验（更快，略降安全）")
    args = ap.parse_args()

    os.makedirs("_tmp_hash160", exist_ok=True)

    jobs=[]
    results=[]
    if args.stdin:
        # 单路 stdin（无法并行拆分；建议用外部并行解压分片）
        results.append(process_file(None, "_tmp_hash160", b58_check=(not args.b58_no_check)))
    else:
        files = sorted({p for pat in args.inputs.split(",") for p in glob.glob(pat.strip())})
        if not files:
            print("No input files matched.", file=sys.stderr); sys.exit(1)
        with Pool(processes=args.workers) as pool:
            for path in files:
                jobs.append(pool.apply_async(process_file,(path,"_tmp_hash160", not args.b58_no_check)))
            pool.close(); pool.join()
        for j in jobs: results.append(j.get())

    # 汇总
    tmp1=[]; tmp2=[]; tmp3=[]
    tot = {'p2pkh':0,'p2sh':0,'p2wpkh':0,'skip':0}
    for path,c1,c2,c3,cx,p1,p2,p3 in results:
        print(f"[+] {os.path.basename(path)}  p2pkh={c1} p2sh={c2} p2wpkh={c3} skip={cx}")
        tot['p2pkh']+=c1; tot['p2sh']+=c2; tot['p2wpkh']+=c3; tot['skip']+=cx
        tmp1.append(p1); tmp2.append(p2); tmp3.append(p3)

    out1=f"{args.out_prefix}_p2pkh.txt"
    out2=f"{args.out_prefix}_p2sh.txt"
    out3=f"{args.out_prefix}_p2wpkh.txt"
    n1=sort_unique(tmp1,out1)
    n2=sort_unique(tmp2,out2)
    n3=sort_unique(tmp3,out3)

    print("\n[*] Done.")
    print(f"    p2pkh (unique): {n1} -> {out1}")
    print(f"    p2sh  (unique): {n2} -> {out2}")
    print(f"    p2wpkh(unique): {n3} -> {out3}")
    print(f"    skipped tokens: {tot['skip']}")

    # 清理临时文件
    for p in tmp1+tmp2+tmp3:
        try: os.remove(p)
        except: pass
    try: os.rmdir("_tmp_hash160")
    except: pass

if __name__=="__main__":
    main()
