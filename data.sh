# 1) 准备目录
mkdir -p ~/bitcoin_richlist && cd ~/bitcoin_richlist

# 2) 写入下载列表
cat > urls.txt <<'EOF'
https://github.com/Pymmdrza/Rich-Address-Wallet/releases/download/Bitcoin/Latest_Bitcoin_Addresses.tsv.gz
https://github.com/Pymmdrza/Rich-Address-Wallet/releases/download/Bitcoin/Latest_Rich_Bitcoin_Address.txt.gz
https://github.com/Pymmdrza/Rich-Address-Wallet/releases/download/Bitcoin/Latest_Rich_Bitcoin_P2PKH.txt.gz
https://github.com/Pymmdrza/Rich-Address-Wallet/releases/download/Bitcoin/Latest_Rich_Bitcoin_P2SH.txt.gz
https://github.com/Pymmdrza/Rich-Address-Wallet/releases/download/Bitcoin/Latest_Rich_Bitcoin_BECH32.txt.gz
EOF

# 3) 并行高速下载（断点续传）
# -x 16 每线程最多16个连接；-s 16 分成16段并发；-k 1M 每段大小；--continue 断点续传
aria2c -i urls.txt -x 16 -s 16 -k 1M --continue=true --summary-interval=0

# 4) 查看下载结果
ls -lh

# 5) （可选）解压全部 .gz
# 如果没安装 pigz 就用 gunzip；pigz 会更快
if command -v pigz >/dev/null 2>&1; then
  pigz -d *.gz
else
  for f in *.gz; do gunzip -v "$f"; done
fi
