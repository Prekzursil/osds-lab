#!/usr/bin/env bash
set -e

echo "=== Exercise 2: Baby's first executable loader ==="
echo
echo "Goal: Build and run ex2, study how it mmaps code from a file and jumps to it (like a tiny loader)."
echo "Inspect the target 'bin/dummy', view its code at a specific offset, and run ex2 to execute mapped bytes."
echo

# Step 1: Build
read -rp $'Step 1) Press ENTER to build ex2 and dummy via Makefile...\n'
make -C ../lab1 ex2 dummy || make -C ../lab1 ex2

# Step 2: Inspect the target payload (dummy)
echo
echo "--- file and readelf on bin/dummy ---"
file ../lab1/bin/dummy || true
readelf -h ../lab1/bin/dummy | sed -n '1,40p'
echo
echo "--- objdump -d (first 200 lines) ---"
objdump -d ../lab1/bin/dummy | sed -n '1,200p' || true

echo
echo "Explanation:"
echo "• dummy is a small ELF with a function we want to execute by mapping bytes and casting to a function pointer."
echo "• The README references an offset (e.g., 0x1106). We'll show those bytes."
echo

# Step 3: Hexdump around offset 0x1106 (if file is large enough)
read -rp $'Step 3) Press ENTER to show bytes around offset 0x1106...\n'
OFFSET=$((0x1106))
dd if=../lab1/bin/dummy bs=1 skip=$OFFSET count=64 status=none | hexdump -C || true

# Step 4: Run ex2
echo
read -rp $'Step 4) Press ENTER to run ./bin/ex2 and observe output...\n'
make -C ../lab1 ex2
../lab1/bin/ex2 || true

echo
echo "Explanation:"
echo "• ex2 mmaps an executable buffer, copies bytes from the file, casts the buffer to a function pointer, and calls it."
echo "• If successful, you should see the function\'s side effects (e.g., prints) from the mapped code."
