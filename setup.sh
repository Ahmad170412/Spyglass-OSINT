#!/usr/bin/env bash
#
# Spyglass setup — macOS & Linux only (Windows is not supported).
#
# What it does:
#   1. Installs the system tools Spyglass wraps (brew on macOS, apt on Debian/Ubuntu)
#   2. Creates a Python virtualenv and installs the Python tool packages
#   3. Clones blackbird (username/email module) into ~/blackbird
#   4. Installs a `spyglass` launcher into ~/.local/bin
#   5. Verifies what's installed and prints a summary
#
# Safe to re-run: every step is idempotent.
#
# Usage:
#   ./setup.sh
#
# Optional controls:
#   SPYGLASS_SKIP_SYSTEM=1   skip package-manager / system tools
#   SPYGLASS_SKIP_PYTHON=1   skip the venv + pip packages
#   SPYGLASS_VENV=path       override the venv location (default: ./.venv)

set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: ./setup.sh"
  echo "  Installs Spyglass's external tools, sets up a venv, and adds a 'spyglass' launcher."
  echo "  Env: SPYGLASS_SKIP_SYSTEM=1  SPYGLASS_SKIP_PYTHON=1  SPYGLASS_VENV=path"
  exit 0
fi

# ── colors (auto-off when stdout is not a TTY) ────────────
if [[ -t 1 ]]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; Z=$'\033[0m'
else
  R=""; G=""; Y=""; C=""; Z=""
fi
info() { printf '%s[*]%s %s\n' "$C" "$Z" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$G" "$Z" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$Z" "$*"; }
die()  { printf '%s[x]%s %s\n' "$R" "$Z" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The import package is a real, valid identifier now — the checkout directory is
# not required to match it, and must not be assumed to. It used to be derived
# from the checkout basename, which only worked because the two always matched;
# the distribution is `spyglass-osint`, the import package is `spyglass`.
PKG_NAME="spyglass"

info "Spyglass setup"
info "Repo: $REPO_DIR"

# ── 1. OS detection ───────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Darwin) OS_NAME="macOS";;
  Linux)  OS_NAME="Linux";;
  *)      die "Unsupported OS: $OS — Spyglass targets macOS and Linux only.";;
esac
ok "OS: $OS_NAME"

# ── 2. bootstrap essentials ───────────────────────────────
have curl || die "curl is required — install it first."
have git  || die "git is required — install it first."

# Prefer the newest Python 3.x available; fall back to plain python3.
PY_BIN=""
for c in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY_BIN="$c"; break; fi
done
[[ -n "$PY_BIN" ]] || die "python3 not found — install Python 3.9+ (3.11 recommended)."

PY_VER="$("$PY_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJ="${PY_VER%%.*}"; PY_MIN="${PY_VER##*.}"
if (( PY_MAJ < 3 || (PY_MAJ == 3 && PY_MIN < 9) )); then
  die "Python $PY_VER is too old — Spyglass needs Python 3.9+."
fi
if (( PY_MAJ == 3 && PY_MIN >= 9 && PY_MIN < 11 )); then
  warn "Python $PY_VER works but is untested; 3.11+ is recommended."
fi
ok "Python $PY_VER ($PY_BIN)"

# ── 3. system tools ───────────────────────────────────────
if [[ "${SPYGLASS_SKIP_SYSTEM:-0}" == "1" ]]; then
  warn "Skipping system tools (SPYGLASS_SKIP_SYSTEM=1)."
else
  if [[ "$OS" == "Darwin" ]]; then
    if ! have brew; then
      info "Homebrew not found — installing (one-time, may take a few minutes)..."
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
        || warn "Homebrew install failed — install it manually, then re-run."
    fi
    if have brew; then
      for t in torsocks exiftool seclists subfinder; do
        info "brew install $t"
        if brew install "$t" >/dev/null 2>&1; then ok "  $t"; else warn "  $t failed (optional)"; fi
      done
      info "brew install projectdiscovery/tap/httpx"
      if brew install projectdiscovery/tap/httpx >/dev/null 2>&1; then ok "  httpx"; else warn "  httpx failed (optional)"; fi
    fi
  else
    if have apt-get; then
      SUDO=""
      [[ "$(id -u)" == "0" ]] || SUDO="sudo"
      info "Installing system tools via apt-get (may prompt for sudo)..."
      $SUDO apt-get update -y >/dev/null || warn "apt-get update failed (continuing)."
      for t in dnsutils whois torsocks libimage-exiftool-perl seclists; do
        info "apt-get install $t"
        if $SUDO apt-get install -y "$t" >/dev/null 2>&1; then ok "  $t"; else warn "  $t failed (optional)"; fi
      done
      # ProjectDiscovery's tools have no distro package; go install is the
      # supported route. subfinder is the important one — it is the primary
      # passive subdomain source and was previously not installed here at all.
      go_install() {
        local name="$1" pkg="$2"
        info "Installing $name via go install..."
        if GO111MODULE=on go install -v "$pkg" >/dev/null 2>&1 \
           && mkdir -p "$HOME/.local/bin" \
           && ln -sf "$HOME/go/bin/$name" "$HOME/.local/bin/$name"; then
          ok "  $name"
        else
          warn "  $name via go failed (optional)"
        fi
      }
      if have go; then
        go_install httpx    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        go_install subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
      else
        warn "httpx and subfinder skipped (need Go) — passive subdomain discovery falls back to crt.sh, CertSpotter, HackerTarget and the Wayback index."
      fi
    elif have dnf; then
      warn "Fedora/RHEL: run 'dnf install bind-utils whois torsocks exiftool seclists' manually, then re-run."
    elif have pacman; then
      warn "Arch: run 'pacman -S bind whois torsocks exiftool seclists' manually, then re-run."
    else
      warn "No supported package manager found — install system tools manually, then re-run."
    fi
  fi
fi

# ── 4. venv + Python packages ─────────────────────────────
VENV="${SPYGLASS_VENV:-$REPO_DIR/.venv}"

if [[ "${SPYGLASS_SKIP_PYTHON:-0}" == "1" ]]; then
  warn "Skipping venv + Python packages (SPYGLASS_SKIP_PYTHON=1)."
else
  if [[ ! -x "$VENV/bin/python" ]]; then
    info "Creating virtualenv: $VENV"
    "$PY_BIN" -m venv "$VENV" || die "venv creation failed."
  fi
  PY="$VENV/bin/python"
  ok "venv: $VENV"

  "$PY" -m pip install --upgrade pip -q || warn "pip upgrade failed (continuing)."

  # Correct PyPI names. sherlock's package is 'sherlock-project'; the rest match
  # the console-script name Spyglass detects on the PATH.
  #
  # Installed one at a time on purpose: these are optional engines, and every
  # module degrades gracefully when its tool is missing, so a single failure must
  # not abort the run. `--no-deps` is NOT used here — the engines need their own
  # trees — but a partial failure is expected and only warns.
  #
  # cryptography is in this list because store.py falls back to plaintext on disk
  # without it, and that fallback should not be what a user gets by default.
  PIP_PKGS=(
    "rich>=13.0.0"
    "phonenumbers>=8.13.0"
    "cryptography>=42.0.0"
    "shodan"
    "holehe"
    "sherlock-project"
    "maigret"
    "user-scanner"
    # 1.2 is the newest release and the last that ships the `ignorant` console
    # script phone.py invokes. This read >=2.0, which no published version
    # satisfies, so it has been failing quietly and the phone module has been
    # running without its footprint source.
    "ignorant>=1.2"
  )
  for p in "${PIP_PKGS[@]}"; do
    info "pip install $p"
    if "$PY" -m pip install -q "$p"; then ok "  $p"; else warn "  $p FAILED — the related module will degrade gracefully."; fi
  done

  # Register the checkout itself. --no-deps because every core dependency is
  # already handled above with per-package error handling, and letting pip
  # re-resolve them would turn one unavailable engine into a failed install.
  if "$PY" -m pip install -q --no-deps -e "$REPO_DIR"; then
    ok "  spyglass (editable, from $REPO_DIR)"
  else
    warn "  could not install the package itself — use 'python -m $PKG_NAME' from $REPO_DIR"
  fi
fi

# ── 5. blackbird (username/email module) ──────────────────
BB_DIR="$HOME/blackbird"
if [[ -f "$BB_DIR/blackbird.py" ]]; then
  ok "blackbird already present: $BB_DIR"
else
  info "Cloning blackbird -> $BB_DIR"
  if git clone --depth 1 https://github.com/p1ngul1n0/blackbird.git "$BB_DIR" >/dev/null 2>&1; then
    ok "  blackbird cloned"
    if [[ -x "$VENV/bin/python" && -f "$BB_DIR/requirements.txt" ]]; then
      if "$VENV/bin/python" -m pip install -q -r "$BB_DIR/requirements.txt" >/dev/null 2>&1; then
        ok "  blackbird deps"
      else
        warn "  blackbird deps failed (blackbird may error at runtime)"
      fi
    fi
  else
    warn "  blackbird clone failed — username/email will use the other tools."
  fi
fi

# blackbird resolves its site list from its own directory and does not ship one,
# so a fresh clone is installed broken: every username search raises
# FileNotFoundError on stderr and reports zero results, which is indistinguishable
# from a handle that genuinely has no profiles. Fetch the WhatsMyName list it
# expects — the same ~717 sites the tool reads from.
BB_DATA="$BB_DIR/data/wmn-data.json"
if [[ -f "$BB_DIR/blackbird.py" && ! -f "$BB_DATA" ]]; then
  info "Fetching blackbird's site list (WhatsMyName)"
  if curl -fsSL --max-time 60 -o "$BB_DATA" \
      "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json" \
      >/dev/null 2>&1; then
    ok "  site list installed ($(wc -c < "$BB_DATA" | tr -d ' ') bytes)"
  else
    warn "  could not fetch the site list — blackbird will report no username results."
  fi
fi

# ── 6. spyglass launcher ──────────────────────────────────
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"
LAUNCHER="$LOCAL_BIN/spyglass"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# Generated by Spyglass setup.sh — re-run setup.sh to regenerate.
export PATH="$VENV/bin:\$PATH"
# Prefer the installed console script. Fall back to \`python -m\` from the
# checkout root, which is where the spyglass/ package lives, if the editable
# install did not take.
if [[ -x "$VENV/bin/spyglass" ]]; then
  exec "$VENV/bin/spyglass" "\$@"
fi
cd "$REPO_DIR" || exit 1
exec "$VENV/bin/python" -m "$PKG_NAME" "\$@"
EOF
chmod +x "$LAUNCHER"
ok "launcher: $LAUNCHER"

SHELL_RC="$HOME/.$(basename "${SHELL:-/bin/sh}")rc"
if [[ -f "$SHELL_RC" ]]; then
  if ! grep -qF '.local/bin' "$SHELL_RC" 2>/dev/null; then
    printf '\n# Spyglass (added by setup.sh)\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$SHELL_RC"
    ok "Added ~/.local/bin to PATH in $SHELL_RC"
  fi
else
  warn "To use 'spyglass' in new shells, add: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# ── 7. verify ─────────────────────────────────────────────
info "Verifying tools (this is what Spyglass will detect):"
venv_bin() { [[ -x "$VENV/bin/$1" ]]; }
found_or_missing() {
  if have "$1" || venv_bin "$1"; then ok "  $1"; else warn "  $1 — missing"; fi
}
for t in dig curl whois torsocks exiftool httpx subfinder phoneinfoga; do
  found_or_missing "$t"
done
for t in shodan holehe sherlock maigret user-scanner ignorant; do
  found_or_missing "$t"
done
if [[ -f "$BB_DIR/blackbird.py" ]]; then ok "  blackbird.py ($BB_DIR)"; else warn "  blackbird.py — missing"; fi
if [[ -f "$BB_DIR/data/wmn-data.json" ]]; then ok "  blackbird site list"; else warn "  blackbird site list — missing (username results will be empty)"; fi

echo
ok "Setup complete."
info "Next steps:"
if [[ -f "$SHELL_RC" ]]; then
  echo "  source $SHELL_RC      # or open a new terminal"
fi
echo "  spyglass --help"
echo "  spyglass website example.com --report"
echo
info "Or without the launcher:"
echo "  cd $REPO_DIR && $VENV/bin/python -m $PKG_NAME --help"
