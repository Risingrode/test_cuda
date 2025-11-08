#!/usr/bin/env bash
# setup-rust.sh — 自动安装 & 配置 Rust 开发环境
set -euo pipefail

# ===== 配置选项 =====
: "${USE_CN_MIRROR:=0}"           # 1=使用国内镜像, 0=官方源
: "${INSTALL_SCCACHE:=1}"         # 1=安装 sccache
: "${INSTALL_MOLD_OR_LLD:=1}"     # 1=尝试安装 mold 或 lld 以加速链接
: "${DEFAULT_TOOLCHAIN:=stable}"  # stable 或 nightly
: "${PROFILE:=minimal}"           # rustup profile: minimal / default / complete

info() { echo -e "\033[1;32m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err () { echo -e "\033[1;31m[ERR ]\033[0m $*"; }

detect_os() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "macOS"; return
  fi
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID_LIKE:-$ID}"
  else
    echo "linux"
  fi
}

# ===== 安装系统依赖 =====
install_deps() {
  local os="$1"
  info "Installing system dependencies for: $os"
  case "$os" in
    *debian*|*ubuntu*)
       apt-get update -y
       apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev curl git ca-certificates cmake clang \
        zlib1g-dev
      if [[ "$INSTALL_MOLD_OR_LLD" == "1" ]]; then
         apt-get install -y mold lld || true
      fi
      ;;
    *rhel*|*centos*|*rocky*|*almalinux*)
       yum -y groupinstall "Development Tools" ||  dnf -y groupinstall "Development Tools" || true
      ( yum -y install openssl-devel pkgconfig curl git cmake clang || \
        dnf -y install openssl-devel pkgconf curl git cmake clang) || true
      if [[ "$INSTALL_MOLD_OR_LLD" == "1" ]]; then
        ( yum -y install mold lld ||  dnf -y install mold lld) || true
      fi
      ;;
    *fedora*)
       dnf -y install @development-tools openssl-devel pkgconf curl git cmake clang
      if [[ "$INSTALL_MOLD_OR_LLD" == "1" ]]; then
         dnf -y install mold lld || true
      fi
      ;;
    *arch*)
       pacman -Sy --noconfirm base-devel openssl pkgconf curl git cmake clang
      if [[ "$INSTALL_MOLD_OR_LLD" == "1" ]]; then
         pacman -Sy --noconfirm mold lld || true
      fi
      ;;
    *alpine*)
       apk add --no-cache build-base openssl-dev pkgconfig curl git cmake clang
      if [[ "$INSTALL_MOLD_OR_LLD" == "1" ]]; then
         apk add --no-cache mold lld || true
      fi
      ;;
    macOS)
      if ! command -v brew >/dev/null 2>&1; then
        err "未检测到 Homebrew，请先安装：https://brew.sh"
        exit 1
      fi
      brew install openssl pkg-config cmake llvm git curl
      if [[ "$INSTALL_MOLD_OR_LLD" == "1" ]]; then
        brew install mold llvm || true
      fi
      ;;
    *)
      warn "未识别的发行版，尝试最少依赖：curl git"
      ;;
  esac
}

# ===== 安装 rustup & toolchain =====
install_rustup() {
  info "Installing rustup & toolchain=$DEFAULT_TOOLCHAIN (profile=$PROFILE)"
  local sh_url="https://sh.rustup.rs"
  if [[ "$USE_CN_MIRROR" == "1" ]]; then
    export RUSTUP_DIST_SERVER="https://rsproxy.cn"
    export RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"
  fi
  curl --proto '=https' --tlsv1.2 -sSf "$sh_url" | sh -s -- -y --profile "$PROFILE" --default-toolchain "$DEFAULT_TOOLCHAIN"
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
  rustup component add clippy rustfmt rust-src || true
  rustup component add rust-analyzer || true
}

# ===== 配置 Cargo 源（可选国内镜像） =====
config_cargo_mirrors() {
  mkdir -p "$HOME/.cargo"
  local cfg="$HOME/.cargo/config.toml"
  if [[ "$USE_CN_MIRROR" == "1" ]]; then
cat > "$cfg" <<'EOF'
[source.crates-io]
replace-with = 'rsproxy-sparse'

[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"

[registries.crates-io]
index = "https://github.com/rust-lang/crates.io-index"

[net]
git-fetch-with-cli = true
EOF
    info "已启用 rsproxy.cn 镜像（sparse）"
  else
cat > "$cfg" <<'EOF'
[net]
git-fetch-with-cli = true
EOF
  fi
}

# ===== 设置 PATH 和常用环境变量 =====
ensure_shell_env() {
  local line='source "$HOME/.cargo/env"'
  for f in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [[ -f "$f" ]] || continue
    grep -Fq "$line" "$f" || echo "$line" >> "$f"
  done

  # 链接器/编译加速
  local cargo_env="$HOME/.cargo/env_extra.sh"
  {
    echo 'export RUSTFLAGS="$RUSTFLAGS -C target-cpu=native"'
    if command -v mold >/dev/null 2>&1; then
      echo 'export RUSTFLAGS="$RUSTFLAGS -C link-arg=-fuse-ld=mold"'
    elif command -v ld.lld >/dev/null 2>&1; then
      echo 'export RUSTFLAGS="$RUSTFLAGS -C link-arg=-fuse-ld=lld"'
    fi
  } > "$cargo_env"

  for f in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [[ -f "$f" ]] || continue
    grep -Fq 'env_extra.sh' "$f" || echo '[[ -f "$HOME/.cargo/env_extra.sh" ]] && source "$HOME/.cargo/env_extra.sh"' >> "$f"
  done
}

# ===== sccache（可选） =====
setup_sccache() {
  if [[ "$INSTALL_SCCACHE" != "1" ]]; then return; fi
  info "Installing sccache (cargo install sccache)"
  cargo install sccache || true
  if command -v sccache >/dev/null 2>&1; then
    local cargo_env="$HOME/.cargo/env_extra.sh"
    grep -Fq 'RUSTC_WRAPPER' "$cargo_env" || {
      echo 'export RUSTC_WRAPPER="sccache"' >> "$cargo_env"
      echo 'export SCCACHE_DIR="${SCCACHE_DIR:-$HOME/.cache/sccache}"' >> "$cargo_env"
    }
  else
    warn "sccache 安装失败，已跳过"
  fi
}

# ===== 简单验证 =====
smoke_test() {
  info "Rust 版本：$(rustc --version || true)"
  info "Cargo 版本：$(cargo --version || true)"
  info "执行 smoke test..."
  tmpdir="$(mktemp -d)"
  pushd "$tmpdir" >/dev/null
  cargo new --quiet hello
  (cd hello && cargo build --quiet)
  info "Smoke test OK：$tmpdir/hello/target/debug/hello"
  popd >/dev/null
}

main() {
  local os; os="$(detect_os)"
  install_deps "$os"
  install_rustup
  config_cargo_mirrors
  ensure_shell_env
  setup_sccache
  smoke_test
  info "Rust 环境安装完成。重新登录或运行 'source ~/.bashrc' 以生效。"
  echo
  echo "提示："
  echo "  - 使用国内镜像： USE_CN_MIRROR=1 bash setup-rust.sh"
  echo "  - 切换到 nightly ： rustup default nightly"
  echo "  - 添加/升级组件 ： rustup component add clippy rustfmt rust-src rust-analyzer"
}

main "$@"
