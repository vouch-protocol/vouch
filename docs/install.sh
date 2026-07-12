#!/bin/sh
# Vouch Protocol installer.
#
#   curl -fsSL https://vouch-protocol.com/install.sh | sh
#
# Installs the `vouch` command line tool. Prefers pipx (an isolated install),
# falls back to pip. Prints the one thing to run next.
set -e

info() { printf '  %s\n' "$1"; }
err() { printf 'Error: %s\n' "$1" >&2; }

printf '\nInstalling Vouch Protocol...\n\n'

# 1. Python 3.9+ is required. We cannot install it for you reliably, so if it
#    is missing we point you at the download and stop.
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  err "Python 3.9 or newer is required, and no python was found."
  info "Install Python from https://www.python.org/downloads/ then run this again."
  exit 1
fi

# 2. Install. pipx keeps the tool in its own environment and puts `vouch` on
#    PATH; it is the smoothest path on modern Linux and macOS. If pipx is not
#    present we use pip.
if command -v pipx >/dev/null 2>&1; then
  info "Installing with pipx..."
  pipx install vouch-protocol >/dev/null
elif "$PY" -m pip --version >/dev/null 2>&1; then
  info "Installing with pip..."
  if ! "$PY" -m pip install --user --upgrade vouch-protocol >/dev/null 2>&1; then
    err "pip could not install into your user environment."
    info "The easiest fix is pipx. Install it, then run this again:"
    info "  $PY -m pip install --user pipx  &&  $PY -m pipx ensurepath"
    exit 1
  fi
else
  err "Neither pipx nor pip is available for $PY."
  info "Bootstrap pip with:  $PY -m ensurepip --upgrade   (see https://pip.pypa.io)"
  exit 1
fi

# 3. Confirm, and show the single next step.
printf '\nVouch Protocol is installed.\n\n'
if command -v vouch >/dev/null 2>&1; then
  info "Run this and pick what you want to do:"
  info "  vouch"
else
  info 'Almost there: the "vouch" command is not on your PATH yet.'
  info "Add your user scripts directory to PATH, then run  vouch :"
  info '  export PATH="$HOME/.local/bin:$PATH"'
fi
printf '\n'
