#!/usr/bin/env bash
set -e

echo "=== Exercise 1: Inspecting Virtual Memory ==="
echo
echo "Goal: Build and run the sample program, then inspect how Linux maps its segments into virtual memory."
echo "Look at ELF headers/sections, and at the process mappings via /proc and in gdb (pwndbg/gef if available)."
echo

# Step 1: Build
read -rp $'Step 1) Press ENTER to build ex1 via Makefile...\n'
make -C ../lab1 ex1

# Step 2: Quick ELF introspection
echo
echo "--- ELF file overview (file) ---"
file ../lab1/bin/ex1 || true

echo
echo "--- readelf -h (ELF header) ---"
readelf -h ../lab1/bin/ex1 | sed -n '1,40p'

echo
echo "--- readelf -S (sections) ---"
readelf -S ../lab1/bin/ex1 | sed -n '1,200p'

echo
echo "Explanation:"
echo "• ELF header tells us architecture, entry point, and format."
echo "• Sections show .text (code), .rodata (const), .data (init globals), .bss (zeroed globals)."
echo

# Step 3: Run ex1 in background (it loops to let us attach/inspect)
LOG="/tmp/ex1.log"
# ensure the log is writable (and avoid stale perms)
: > "$LOG" || { echo "[!] Cannot write $LOG"; exit 1; }
chmod 666 "$LOG" 2>/dev/null || true
echo "[i] Logging ex1 output to: $LOG"

# Start the program, keep the REAL ex1 PID, and tee output to the log.
# (Process substitution keeps $! as ex1's PID, not tee's.)
stdbuf -oL -eL ./bin/ex1 > >(tee -a "$LOG") 2>&1 &
PID=$!
echo "$PID" > .ex1.pid
echo "[i] ex1 started as PID $PID"

# Step 4: /proc maps
echo
echo "--- /proc/$PID/maps ---"
read -rp $'Step 4) Press ENTER to view /proc/$PID/maps...\n'
cat /proc/$PID/maps | sed -n '1,200p'

echo
echo "Explanation:"
echo "• Each line shows a virtual memory region: start-end addresses, permissions (rwx), offset, device, inode, and pathname."
echo "• You should see segments for the binary, libc, ld loader, stack, heap, and [vdso]/[vvar]."
echo

# Step 5: /proc smaps (first 120 lines)
read -rp $'Step 5) Press ENTER to view /proc/$PID/smaps (first 120 lines)...\n'
sed -n '1,120p' /proc/$PID/smaps || true

echo
echo "Explanation:"
echo "• smaps provides per-region details: Size, Rss, Pss, Shared_Clean/Dirty, Private_Clean/Dirty, etc."
echo


# --- Step 6: attach gdb, show mappings, and answer Q2 (symbols + call) ---
echo
echo "--- GDB memory view ---"
read -rp $'Step 6) Press ENTER to attach gdb (detach with q). We will try vmmap if pwndbg/gef is present, otherwise use: info proc mappings\n'

# Resolve target PID robustly
if [ -z "${PID:-}" ]; then
  [ -f .ex1.pid ] && PID="$(cat .ex1.pid 2>/dev/null)"
fi
[ -z "${PID:-}" ] && PID="$(pgrep -n ex1 || true)"
if [ -z "${PID:-}" ]; then
  echo "[!] ex1 is not running. Start Step 3 first."
  exit 1
fi
echo "[i] Attaching to ex1 PID: $PID"

CMD_FILE="$(mktemp)"
cat > "$CMD_FILE" <<'GDBCMD'
set pagination off
set confirm off
attach $PID

# Show memory layout (vmmap if pwndbg/gef; otherwise fallback)
python
import gdb
try:
    gdb.execute("vmmap")
except gdb.error:
    gdb.write("[*] 'vmmap' unavailable; falling back to 'info proc mappings'\n")
    gdb.execute("info proc mappings")
end

# --- Q2: locate symbols and call bar(3, useful) ---
echo \n--- Q2: symbols & call demo ---\n
echo address of bar():\n
p (void*)&bar
echo \ndisassembly of bar():\n
disassemble bar
echo \naddress of useful:\n
p &useful
echo \nstring at useful:\n
x/s &useful
echo \ncalling bar(3, useful):\n
call (void)bar(3, &useful[0])

detach
quit
GDBCMD

# Substitute the real PID (NO QUOTES!)
sed -i "s/attach \$PID/attach $PID/g" "$CMD_FILE"

# Use sudo only for the attach (keeps your logger happy)
if [ "$(id -u)" -ne 0 ]; then
  sudo gdb -q -x "$CMD_FILE" || true
else
  gdb -q -x "$CMD_FILE" || true
fi
rm -f "$CMD_FILE"




# Step 7: Cleanup
echo
read -rp $'Step 7) Press ENTER to stop ex1...\n'
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

echo
echo "Result: You built ex1, inspected ELF structure, and examined the live process\'s memory layout via /proc and gdb."
