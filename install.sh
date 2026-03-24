#!/bin/sh
# Cybermonkey – Hera Installer
# Usage: curl -fsSL https://get.cybermonkey.sh/hera | sh
#
# Hera is a Chrome extension for authentication security monitoring —
# detects vulnerabilities in OAuth2, OIDC, SAML, SCIM, and WebAuthn flows.
#
# Human Technology — https://cybermonkey.sh

set -eu

REPO="hera"
DESCRIPTION="Auth Security Chrome Extension"
GITEA="https://gitea.cybermonkey.sh/cybermonkey"
BRANCH="main"
INSTALL_DIR="${CYBERMONKEY_HOME:-$HOME/.cybermonkey}/${REPO}"

if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
  BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

info()  { printf "${BLUE}ℹ${RESET}  %s\n" "$*"; }
ok()    { printf "${GREEN}✔${RESET}  %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${RESET}  %s\n" "$*"; }
err()   { printf "${RED}✖${RESET}  %s\n" "$*" >&2; }
fatal() { err "$@"; exit 1; }

banner() {
  printf "\n${BOLD}"
  cat <<'ART'
   ╔═══════════════════════════════════════════╗
   ║   🐵  Cybermonkey · Hera Installer       ║
   ║       Human Technology                    ║
   ╚═══════════════════════════════════════════╝
ART
  printf "${RESET}\n"
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || fatal "'$1' is required but not found."; }

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else fatal "Neither curl nor wget found."; fi
}

preflight() {
  info "Checking prerequisites…"
  need_cmd git
  # Node.js needed for building
  if command -v node >/dev/null 2>&1; then
    NODE_VER=$(node --version)
    ok "Node.js found: ${NODE_VER}"
  else
    warn "Node.js not found — you'll need it to build the extension"
  fi

  if command -v npm >/dev/null 2>&1; then
    ok "npm found"
  elif command -v yarn >/dev/null 2>&1; then
    ok "yarn found"
  else
    warn "npm/yarn not found — needed for dependency installation"
  fi
}

install() {
  info "Installing ${DESCRIPTION} to ${INSTALL_DIR}…"

  if [ -d "${INSTALL_DIR}/.git" ]; then
    info "Existing installation found — pulling latest…"
    (cd "$INSTALL_DIR" && git pull origin "$BRANCH") || warn "Pull failed — continuing with existing version"
  else
    mkdir -p "$(dirname "$INSTALL_DIR")"
    info "Cloning repository…"
    git clone --depth 1 -b "$BRANCH" "${GITEA}/${REPO}.git" "$INSTALL_DIR" 2>/dev/null \
      || git clone --depth 1 -b "$BRANCH" "https://gitea.cybermonkey.sh/cybermonkey/${REPO}.git" "$INSTALL_DIR"
  fi
  ok "Source code downloaded to ${INSTALL_DIR}"

  # Install dependencies and build
  if [ -f "${INSTALL_DIR}/package.json" ]; then
    info "Installing npm dependencies…"
    (cd "$INSTALL_DIR" && npm install --no-fund --no-audit 2>/dev/null) \
      && ok "Dependencies installed" \
      || warn "npm install failed — you may need to install manually"

    # Build extension if build script exists
    if grep -q '"build"' "${INSTALL_DIR}/package.json" 2>/dev/null; then
      info "Building extension…"
      (cd "$INSTALL_DIR" && npm run build 2>/dev/null) \
        && ok "Extension built" \
        || warn "Build failed — you may need to build manually"
    fi
  fi

  ok "${DESCRIPTION} installed to ${INSTALL_DIR}"
}

post_install() {
  # Detect build output directory
  DIST_DIR="${INSTALL_DIR}/dist"
  if [ ! -d "$DIST_DIR" ]; then
    DIST_DIR="${INSTALL_DIR}/build"
  fi
  if [ ! -d "$DIST_DIR" ]; then
    DIST_DIR="$INSTALL_DIR"
  fi

  printf "\n${BOLD}Next steps — Load as unpacked Chrome extension:${RESET}\n"
  printf "  1.  Open Chrome and navigate to:\n"
  printf "        ${BLUE}chrome://extensions/${RESET}\n"
  printf "  2.  Enable ${BOLD}Developer mode${RESET} (top-right toggle)\n"
  printf "  3.  Click ${BOLD}Load unpacked${RESET}\n"
  printf "  4.  Select this folder:\n"
  printf "        ${GREEN}%s${RESET}\n" "$DIST_DIR"
  printf "  5.  Pin the extension from the toolbar\n\n"
  printf "  To update later:\n"
  printf "        ${YELLOW}cd %s && git pull && npm run build${RESET}\n" "$INSTALL_DIR"
  printf "        Then click ↻ Reload on chrome://extensions/\n\n"
  printf "  Docs: ${BLUE}${GITEA}/${REPO}${RESET}\n\n"
}

main() {
  banner
  preflight
  install
  post_install
  ok "Done! 🐵"
}

main "$@"
