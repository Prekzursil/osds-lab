#!/usr/bin/env bash
set -e

echo "=== Exercise 3: Stacks, calling conventions, and steering calls ==="
echo
echo "Goal: Build and run ex3, then inspect frames/regs in gdb, observe calls,"
echo "      show SysV AMD64 arg registers, and provoke a SIGSEGV on bad %s."
echo

# Step 1: Build
read -rp $'Step 1) Press ENTER to build ex3 via Makefile...\n'
make -C ../lab1 ex3 || make -C ../lab1
echo "[i] Built ./bin/ex3 with -g -no-pie (per your Makefile)."

# Step 2: Run once (normal)
echo
read -rp $'Step 2) Press ENTER to run ./bin/ex3 once (normal execution)...\n'
../lab1/bin/ex3 || true

# Prepare a non-interactive input for gdb runs
echo "prekzursil" > .ex3.in

# Step 3: Guided GDB session (answers Q4 & Q5)
echo
read -rp $'Step 3) Press ENTER to start a guided gdb session (auto-prints what you need for Q4/Q5)...\n'

GDB_CMDS="$(mktemp)"
cat > "$GDB_CMDS" <<'GDBCMD'
set pagination off
set confirm off
set disassemble-next-line on
handle SIGSEGV stop print nopass

echo \n[+] start at main\n
start

echo \n[+] breakpoints for call-chain inspection\n
break advertisment
tbreak print_msg
break printf

echo \n[+] run with prepared input\n
run < .ex3.in

echo \n[Q4] At advertisment(): show SysV AMD64 arg registers\n
info registers rdi rsi rdx rcx r8 r9

echo \n[Q4] Disassemble and step into a real 'call'\n
disassemble
display/i $pc
ni
ni
si
bt

echo \n[Q4] Continue to print_msg() (tbreak ensures we land there, even if printf would trigger)\n
continue

echo \n[Q4] In print_msg(char*): dump arg pointer and string\n
p $rdi
x/s $rdi

echo \n[Q4] Manually invoke advertisment(2, \"DemoUser\") without tripping bps\n
python
for bp in (gdb.breakpoints() or []):
    bp.enabled = False
end
call (void)advertisment(2, "DemoUser")

echo \n[Q5] Provoke SIGSEGV: bad %%s pointer to print_msg\n
call (void)print_msg((char*)0xdeadbeef)

echo \n[Q5] Backtrace + mappings after crash\n
bt
python
import gdb
try:
    gdb.execute("vmmap")
except gdb.error:
    gdb.write("[*] 'vmmap' unavailable; using 'info proc mappings'\n")
    gdb.execute("info proc mappings")
end
quit
GDBCMD

gdb -q ../lab1/bin/ex3 -x "$GDB_CMDS" || true
rm -f "$GDB_CMDS"


echo
echo "Explanation:"
echo "• [Q4] You’ll see RDI/RSI/... holding the function args per the SysV AMD64 ABI."
echo "• [Q4] 'disassemble' shows the call instructions; the break on printf confirms the chain."
echo "• [Q4] We also call advertisment(2, \"DemoUser\") from gdb to prove we can steer calls."
echo "• [Q5] Calling print_msg((char*)0xdeadbeef) triggers a SIGSEGV in printf (bad %s pointer)."
echo "       The backtrace shows print_msg → printf, and vmmap/info proc mappings confirms"
echo "       the address isn’t mapped."

