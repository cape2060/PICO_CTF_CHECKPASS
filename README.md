# checkpass — picoCTF Writeup

> **Challenge:** checkpass  
> **Category:** Reverse Engineering  
> **Difficulty:** Hard  
> **Flag format:** picoCTF{...}  
> **Tools:** pwndbg, Python 3  

---

## Table of Contents

1. [File Information](#1-file-information)
2. [Initial Analysis](#2-initial-analysis)
3. [Finding Main — The Hard Way](#3-finding-main--the-hard-way)
4. [Understanding the Validation Logic](#4-understanding-the-validation-logic)
5. [Understanding the Cipher](#5-understanding-the-cipher)
6. [Extracting Tables from Memory](#6-extracting-tables-from-memory)
7. [Extracting the Encrypted Flag](#7-extracting-the-encrypted-flag)
8. [Writing the Exploit](#8-writing-the-exploit)
9. [Getting the Flag](#9-getting-the-flag)
10. [Key Takeaways](#10-key-takeaways)

---

## 1. File Information

```bash
$ file checkpass
checkpass: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, BuildID[sha1]=9b785516be1817e2787e9465bd803afd37042d0c,
stripped

$ checksec checkpass
[*] '/home/hacker/Desktop/pico_ctf/Checkpass/checkpass'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

**Key observations:**
- **Stripped** — no function names, no symbols, no debug info
- **PIE enabled** — base address randomized every run
- **NX enabled** — no shellcode execution
- **No canary** — stack not protected but not relevant here

---

## 2. Initial Analysis

Since the binary is stripped, static analysis tools like Binary Ninja show almost nothing useful — no function names, no clear entry point to `main`. Dynamic analysis with pwndbg was the only reliable path.

```bash
$ pwndbg ./checkpass
```

---

## 3. Finding Main — The Hard Way

### Step 1 — starti

```bash
pwndbg> starti
```

This pauses execution at the very first instruction of the binary (`_start`).

### Step 2 — Step to `__libc_start_main`

Used `ni` (step over) repeatedly until reaching the call to `__libc_start_main`:

```bash
pwndbg> ni   # repeat until __libc_start_main call
```

At this point, the **RDI register holds the address of main** — this is the standard x86-64 Linux calling convention where the first argument to `__libc_start_main` is the main function pointer.

```
lea rdi, [rip + offset]     ← RDI = address of some function
call __libc_start_main
```

### Step 3 — Break at RDI address

```bash
pwndbg> b *<rdi_address>
pwndbg> c
```

Landed at the function RDI pointed to. This was **not main** — it was an intermediate wrapper function. Stepping through it with `ni`, one particular `CALL` instruction caused the program to exit printing the usage message:

```
Usage: ./checkpass <password>
```

This confirmed that **this CALL was doing the real work** — it contained the actual program logic.

### Step 4 — Dig deeper with si

Repeated the process — ran back to that address and used `si` (step into) instead of `ni` to enter the function:

```bash
pwndbg> si    # step INTO the call
```

Inside this function, another `CALL` again caused the program to exit with the usage message when stepped over. Stepped into that one too.

This pattern repeated **multiple times** — each layer contained one real `CALL` buried among other instructions, and stepping into it revealed another layer:

```
wrapper_1()
    └── wrapper_2()
          └── wrapper_3()
                └── wrapper_4()
                      └── main()   ← real logic here
```

After stepping into **4 nested calls**, the real `main` function was finally reached — identified because it contained actual program logic and the usage print was triggered from here when no argument was provided.

---

## 4. Understanding the Validation Logic

### Running with an argument

Now that main was found, the program was run with a test argument:

```bash
pwndbg> r hello
```

Stepping through main revealed the following validation checks:

### Check 1 — Length must be exactly 41

```
if len(argv[1]) != 41:
    print("Invalid")
    exit
```

Test with 41 character input:

```bash
pwndbg> r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
#          |-------- 41 chars ---------|
```

### Check 2 — Must start with `picoCTF{`

```
if argv[1][:8] != "picoCTF{":
    print("Invalid")
    exit
```

### Check 3 — Must end with `}`

```
if argv[1][-1] != "}":
    print("Invalid")
    exit
```

Test with properly formatted input:

```bash
pwndbg> r picoCTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}
#                  |-------- 32 chars ---------|
```

This passed all three checks. The program then **stripped the prefix and suffix**, leaving only the 32 inner characters, and passed them to the encryption function.

---

## 5. Understanding the Cipher

After all validation checks passed, the inner 32 bytes were passed to an encryption function. Tracing through this function revealed a **4-round SP-network (Substitution-Permutation Network)** cipher:

```
Input (32 bytes)
      ↓
  Round 1: Permutation (rcx_600) → Substitution (first_data S-box)
      ↓
  Round 2: Permutation (rcx_700) → Substitution (second_data S-box)
      ↓
  Round 3: Permutation (rcx_800) → Substitution (third_data S-box)
      ↓
  Round 4: Permutation (rcx_900) → Substitution (last_data S-box)
      ↓
Encrypted output compared against hardcoded encrypted flag
      ↓
Match → "Success!"
```

Each round consists of:
- **Permutation layer** — reorders the 32 bytes according to a lookup table
- **Substitution layer** — replaces each byte using a 256-byte S-box

To decrypt, all 4 rounds needed to be reversed in order.

---

## 6. Extracting Tables from Memory

All tables were extracted directly from process memory using pwndbg while the binary was paused mid-execution.

### S-boxes (4 × 256 bytes = 1024 bytes total)

```bash
pwndbg> x/32gx 0x55555555c6f0   # first_data
pwndbg> x/32gx 0x55555555c7f0   # second_data
pwndbg> x/32gx 0x55555555c8f0   # third_data
pwndbg> x/32gx 0x55555555c9f0   # last_data
```

Each 64-bit value was split into 8 individual bytes in **little endian** order.

### Permutation tables (4 × 32 entries)

```bash
pwndbg> x/32gx 0x55555555d600   # rcx_600
pwndbg> x/32gx 0x55555555d700   # rcx_700
pwndbg> x/32gx 0x55555555d800   # rcx_800
pwndbg> x/32gx 0x55555555d900   # rcx_900
```

Each entry is a 64-bit value representing a single byte index. Keys increase by `0x08` (8 bytes) each entry reflecting the 64-bit memory layout.

---

## 7. Extracting the Encrypted Flag

The hardcoded encrypted flag was also found in memory and extracted:

```bash
pwndbg> x/4gx 0x7fffffffd920
```

The encrypted bytes were scattered in memory indexed by position. They were collected into a dictionary keyed by position, sorted ascending, then converted to an ordered list:

```python
cat = {
    0x00: 0x1f,  0x01: 0x01,  0x02: 0x50,  0x03: 0x99,
    0x04: 0xb8,  0x05: 0x22,  0x06: 0x3a,  0x07: 0xcb,
    # ... all 32 entries
}

sort      = dict(sorted(cat.items()))
sort_list = list(sort.values())
# sort_list = rdi input to exploit
```

---

## 8. Writing the Exploit

To decrypt the flag, all 4 rounds of the SP-network were reversed in **reverse order** (round 4 → round 3 → round 2 → round 1):

```python
# reverse() → undoes the permutation layer
# reverse1() → undoes the substitution layer using .index()
#              (inverse S-box lookup)

rdi    = sort_list   # encrypted flag bytes

sp     = reverse(rcx_900, rdi)
output = reverse1(last_data, sp)

cat    = [ord(i) for i in output]
sp     = reverse(rcx_800, cat)
output = reverse1(third_data, sp)

cat    = [ord(i) for i in output]
sp     = reverse(rcx_700, cat)
output = reverse1(second_data, sp)

cat    = [ord(i) for i in output]
sp     = reverse(rcx_600, cat)
output = reverse1(first_data, sp)

print('picoCTF{' + "".join(output) + '}')
```

The key insight for inverting the S-box:

```python
# Forward S-box: sbox[input] = output
# Inverse S-box: sbox.index(output) = input  ✅
output[i] = chr(rax.index(int(al.split('x')[1], 16)))
```

---

## 9. Getting the Flag

```bash
$ python3 exploit.py
picoCTF{XXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

Flag submitted successfully ✅

---

## 10. Key Takeaways

- **Stripped binaries hide main** — when RDI at `__libc_start_main` does not point directly to main, the real main is buried in nested wrapper calls. Keep stepping into each suspicious CALL until you find it.
- **Usage message is your friend** — every time the program printed usage and exited, it confirmed that CALL contained real program logic worth stepping into.
- **SP-networks are reversible** — given the S-boxes and permutation tables, any SP-network cipher can be fully decrypted by inverting each operation in reverse round order.
- **`.index()` inverts an S-box** — instead of building a separate inverse table, Python's `.index()` method performs the inverse lookup directly.
- **All data lives in memory** — even when static analysis fails completely, pwndbg can dump any table, buffer, or constant from process memory at runtime.
- **PIE + stripped does not mean uncrackable** — PIE randomizes addresses but pwndbg resolves them at runtime. Stripped removes symbols but dynamic analysis does not need them.

---

*Solved using pure dynamic analysis in pwndbg — no decompiler, no angr, no shortcuts.*
