
# PS4 13.02 — findings summary
bel · jb.0d01.wtf · @belsploit
Firmware tested: 13.02 (comparisons: 13.52, 13.04)

---

## Verified kernel bugs

### 1. Fahrenheit — 32-bit allocation wrap in `ffs_mountfs`

**What it is.** PS4 13.02's UFS2 mount path allocates the cylinder-group
summary buffer with 32-bit arithmetic. The multiply `fs_ncg * 4` can
wrap, shrinking the allocation. The downstream write loop derives its
length from `fs_bsize` and `fs_frag`, neither of which is bounds-checked
against the allocation size. A crafted superblock with
`fs_bsize > fs_fsize * fs_frag` produces a heap overrun of roughly
`N * fs_bsize - allocation` bytes.

**How it was verified.** Decompile both firmwares side by side.

13.02 (`FUN_00ae9510`, base 0 in the dump), allocation:
```c
iVar9  = *(int *)(lVar21 + 0x9c);
iVar24 = (iVar9 + -1 + *(int *)(lVar21 + 0x34)) / *(int *)(lVar21 + 0x34);
if (0 < *(int *)(lVar21 + 0x524)) {
    iVar9 = iVar9 + *(int *)(lVar21 + 0x2c) * 4;      // 32-bit multiply
}
local_5c = iVar9 + *(int *)(lVar21 + 0x2c);
piVar13 = (int *)FUN_00809520((long)(int)local_5c,0x223f8f0,2);
```

13.52 (`FUN_ffffffff824e9640`), allocation:
```c
uVar24 = (ulong)*(uint *)(lVar21 + 0x2c) * 4;          // 64-bit multiply
piVar18 = (int *)FUN_ffffffff82209520(
    uVar24 + (long)iVar11 + (ulong)*(uint *)(lVar21 + 0x2c), &DAT_ffffffff83c3f8f0, 2);
```

The `(ulong)` cast on `fs_ncg` before the multiply is the fix. Same
fields, same structure layout, different integer width.

**Field offsets (within the superblock struct):**
| offset | field | role |
|---|---|---|
| 0x2c | fs_ncg | drives the 32-bit multiply |
| 0x30 | fs_bsize | per-iteration write size |
| 0x34 | fs_fsize | divisor |
| 0x38 | fs_frag | loop step |
| 0x9c | field_0x9c | allocation-size driver |
| 0x3e8 | unlabeled | compared against a geometry-derived value |
| 0x524 | flag | gates the `fs_ncg * 4` branch |
| 0x528 | flag | must be >= 1 |
| 0x55c | fs_magic | 0x19540119 (UFS2) |

**The five inline checks on 13.02** (at `LAB_00ae98b1`):
```c
if ((((*(int *)(lVar14 + 0x55c) != 0x19540119) ||
      (*(ulong *)(lVar14 + 1000) != uVar25)) ||
     (0x10000 < (int)*(uint *)(lVar14 + 0x30))) ||
    ((*(uint *)(lVar14 + 0x30) < 0x560 ||
      (*(int *)(lVar14 + 0x528) < 1))))
    goto LAB_00ae9890;
```
The 13.52 version calls `ffs_validate_sblock` and discards its return
value (fail-open). 13.02 has no such call at all.

**Reachability status.** USB insertion on 13.02 does **not** reach
`ffs_mountfs`. Verified on hardware 2026-09-16: a 32 GB USB drive with
a correctly partitioned (MBR, type 0xA5) UFS2 filesystem, superblock
patched to the overflow geometry, produces only the "format to exFAT"
prompt on insert. No panic, no used-space value, no partial mount.
Either UFS is not on the automounter's probe list, or it is probed and
rejected before `ffs_mountfs`. Distinguishing requires UART. The only
remaining path is the internal HDD mount at boot, which needs a prior
jailbreak to modify the raw partition.

**Unverified.** The 32-bit claim rests on the Ghidra decompile. A single
disassembly of the multiply instruction at the allocation site in
13.02 confirms or refutes it. Until that's done, the finding is
decompile-level evidence.

---

### 2. oomfie — unbounded stack write in `sys_ipmimgr`

**What it is.** Syscall 622 (`sys_ipmimgr`), command 0
(`syscallCreateServer`), walks the pending-connect list and writes two
`uint32` per matching entry into two adjacent 256-byte stack arrays.
The write index (`r12` on 13.02) is never compared against 64. With
64+ matching entries the writes overflow; with 79+ the stack canary
trips. The values written are the `(server_id, uid)` identity pair from
the pending entries. A second loop reads the arrays back and writes
them into freshly allocated `ConnectRequest` objects at offsets
`+0x18` and `+0x1c`. The free path is a bare `uma_zfree` with no
unlink, no refcount, no state check. An identity collision that leads
a caller to free the wrong object is a UAF precondition.

**How it was verified.** Instruction-level disassembly, both firmwares.

13.02:
- Dispatcher: `FUN_00f061d0`
- `syscallCreateServer`: `FUN_00efb220`
- `syscallConnectWithWaitServer`: `FUN_00ef10d0`
- `server_list`: `_DAT_022fdf68`
- List head: `+0x38`, tail: `+0x40`, counter: `+0x34`
- Stack arrays: `RBP-0x170` and `RBP-0x270` (256 bytes each)
- Allocator: `FUN_00ef74d0`, zone pointer at `DAT_02f7d630`
- Free: `FUN_00ef74b0` → `FUN_00a111b0` (bare `uma_zfree`)

13.04 (`1304k.elf`) — same layout, KASLR-slid addresses:
- `server_list`: `DAT_ffffffff83cfdf68`
- `syscallConnectWithWaitServer`: `FUN_ffffffff828f10d0`
- Allocator: `FUN_ffffffff828f74d0`
- Free: `FUN_ffffffff828f74b0`
- ConnectRequest layout identical: `+0x10 = 0x40`, `+0x18 = server_id`,
  `+0x1c = uid`

**The nine callers of `FUN_00ef74b0`** (13.02) — the candidates for
the UAF-trigger site:
```
FUN_00ef10e4   FUN_00ef4260   FUN_00efa000
FUN_00efc840   FUN_00f013f0   FUN_00f030a0
FUN_00f04840   FUN_00f08de0   FUN_00f0a720
```
The UAF requires one that resolves identity by `(server_id, uid)` and
then frees. The disconnect path (`ipmimgr_disconnect.c`) is the most
likely candidate.

**Verification status.** The stack write, the unbounded counter, the
credential bypass, and the UAF precondition are all verified at
instruction level. The specific trigger — which caller frees the wrong
object — is not traced.

**Reachability status.** Blocked on a userspace primitive. No hardware
needed, but issuing the syscalls requires either a browser sandbox
escape or a payload that can run code on the console.

---

## Verified negatives (worth documenting so nobody repeats them)

### 3. msdosfs LFN overflow — not in the 13.02 binary

The FreeBSD 9 `mbnambuf_write` overflow (fixed upstream in 2016) is
**not reachable on 13.02** because the function is not compiled into
the kernel image. The port is a single amalgamated file,
`msdosfs_reference_vfsops.c`, containing the VFS skeleton and FAT
allocation, not the long-filename conversion layer.

**How it was verified.** Ten independent binary searches, all negative
in the msdosfs address range (`0x00b6...`–`0x00b8...`):

| search | result in msdosfs range |
|---|---|
| string `mbnambuf` | 0 |
| string `win2unixfn` / `unix2dosfn` | 0 |
| string `msdosfs_conv.c` | 0 |
| `6B ?? 0D` (IMUL reg, 0xD) | 0 |
| `48 6B ?? 0D` (IMUL r64, 0xD) | 0 |
| `69 ?? ?? 0D 00 00 00` (IMUL imm32) | 0 |
| `C1 ?? 0D` (SHL/SHR/SAR 13) | 0 |
| two adjacent `F3 A4` (REP MOVSB) | 0 |
| two adjacent `CALL FUN_00800ac0` (memmove) | 0 |
| `8d 4c 81 f3` (13x LEA, second half) | 0 |

**Contrast case.** Sony's exfat driver has the LFN machinery and all
its fingerprints:
- LFN serializer: `FUN_00b35a50`, with `8d 04 49` / `8d 4c 81 f3` at
  `0xb35a63` / `0xb35a67` (the 13x computation)
- LFN writer entry point: `FUN_00b35370` (`_write_fat_lfn`)
- Full function-name strings: `_write_fat_lfn`, `_write_fat_metadata`,
  `_write_exfat_name`, etc., in the `0x00fd8f...`–`0x00fd90...` range

The msdosfs port has none of this. The exfat driver has all of it. The
asymmetry is the finding.

**Other msdosfs references for future work:**
- `msdosfs_mount`: `FUN_00b6b1a0`
- `msdosfs_unmount`: `FUN_00b6b8d0`
- `msdosfs_reference_vfsops.c` string: `0x00fde67b`
- Mount-options parser that accepts `longname`/`kiconv` flags:
  `FUN_00a3e000` (parses flags but no consumer exists)

---

### 4. SSV exploit — dead on 13.02

The slopkit SSV exploit (duplicate-reference deserialization) fails on
13.02 because the JavaScriptCore deserializer's `SerializationContext::
m_objectPool` is a `HashMap` in Safari 605.1.15, not a fixed-capacity
array. It deduplicates correctly; the duplicate reference at
`outerGraph[2]` resolves to the same object as `outerGraph[1]`. No
fresh allocation is produced for the heap groom to place.

**How it was verified.** K sweep on hardware. Five cold boots at
`K = 2, 3, 5, 7, 8` with `?slots=9000000&g=drain:512`, plus K=9 as a
bonus data point. Every run returned `NORMAL-CLONE-MISS
known-reference-returned=true`. Every `writer-ref` value matched the
requested K (`0xfffe` for 2, `0xfffd` for 3, `0xfffb` for 5, `0xfff9`
for 7, `0xfff7` for 9), so K was being read correctly. Two rolls per
tested K, both producing the same tag. Total: 11 valid runs, zero
exceptions.

The alternative (encoding-width) hypothesis predicted `Unable to
deserialize data` at some K != 2. That tag never appeared.

**Postmortem source.** thebelx/OnePS postmortem, "OnePS on 13.02:
Death=(true)" — `github.com/thebelx/OnePS`.

---

### 5. netcontrol UAF — patched on 13.02

The `netcontrol` conditional-fdrop patch is present in 13.02's SET
handler. The `if (local_44 != 0 || uaf_failed) fdrop(file);` line makes
the SET+CLEAR pair net 0 instead of net -1, eliminating the UAF. Every
run of chain_poops.js on 13.02 prints `ALIAS-PROBE partner=-` and stops.

**Verification.** Disassembly of `FUN_00964d10` (SET) and `FUN_00964de0`
(CLEAR). SET does `fget +1`, stores the file pointer, does not drop the
fget ref on the fresh-store path. CLEAR does `fget +1`, memsets the
slot without a refcount op, then drops twice. Net 0.

---

### 6. `pru_bind` sockaddr retention — refuted

The OnePS premise that `pru_bind` retains a pointer to the user
sockaddr is false. On 13.52, `tcp6_usr_bind` (resolved from the
`tcp6_usrreqs` table at `0xffffffff83c2fcd8`, slot `+0x18`) reads the
sockaddr fields directly from the user pointer, then passes the raw
pointer to `in6_pcbbind` (`FUN_ffffffff824c8b00`), which reads the
fields again and copies the address and port into the `inpcb` at
`+0xc4`, `+0xc6`, `+0xd4`, `+0xe4`. After `bind()` returns, no kernel
structure holds a pointer to the user sockaddr.

**Verification.** Decompilation of both functions against the 13.52
kernel dump.

---

### 7. TCP disconnect race — null-then-free, not UAF

`in_pcbdetach` (`FUN_ffffffff82426100`) nulls `so->so_pcb` before
`in_pcbfree` (`FUN_ffffffff824262b0`) runs in every branch. A racer
that wins the timing window gets `NULL`, not a dangling pointer. The
subsequent `*(NULL + 0x30)` is a kernel panic, not a UAF.

```c
void in_pcbdetach(long inp) {
    *(undefined8 *)(*(long *)(inp + 0x58) + 0x18) = 0;   // so->so_pcb = NULL
    *(undefined8 *)(inp + 0x58) = 0;                     // inp->inp_socket = NULL
    return;
}
```

**Verification.** Decompilation of `in_pcbdetach` and `in_pcbfree`.

---

### 8. Bagagwa AIO exploit — PS5-only

`aio_multi_wait` mode 0 (the UAF that Bagagwa abuses) exists only on
PS5. PS4 13.52's `aio_multi_wait` (`FUN_ffffffff8231f710`) reads
`uap[0]`, `uap[8]`, `uap[0x10]` and stops — 3 arguments, no mode
parameter. The entire multi-mode `set_waiter` machinery is new PS5
code.

**Verification.** Decompilation of the 13.52 PS4 version against the
PS5 disassembly in the Bagagwa writeup.

---

## The shared blocker

All three verified kernel bugs — Fahrenheit, oomfie, and the
would-be msdosfs LFN — depend on one thing: **a userspace primitive
on 13.02**.

- Fahrenheit needs a way to reach the mount path from userspace,
  which requires either USB probing (closed) or a prior jailbreak.
- oomfie needs a way to issue syscall 622 from userspace. No hardware
  required, but no code path exists today.
- A fresh JSC bug would bypass SSV entirely, but it's a multi-month
  project.

The SSV exploit was the current best candidate for that primitive. It's
dead on 13.02 (see §4). The alternatives — BD-J, a fresh JSC bug, or
another WebKit surface — all require either hardware or months of work.

---

## What's unverified

- **Fahrenheit 32-bit claim.** One disassembly of the multiply at the
  allocation site confirms or refutes the entire finding. Highest-value
  check that hasn't been done.
- **Automounter probe depth.** Whether UFS is on the USB automounter's
  probe list, or whether it's probed and rejected before `ffs_mountfs`.
  Requires UART to distinguish.
- **oomfie UAF trigger.** Which of the nine callers resolves identity
  before freeing. Requires decompiling each caller's lookup path.
- **Fahrenheit exploit chain.** Even with reachability confirmed, the
  path requires heap shaping and a consumer. Neither exists today.

---

## Pointers to the artifacts

- **13.02 kernel dump:** public; strings and disassembly referenced in
  this document are all from this dump.
- **13.04 kernel dump (`1304k.elf`):** used for the oomfie layout
  cross-reference (§2). Same module offsets, KASLR-slid.
- **13.52 kernel dump:** used for Fahrenheit comparison (§1), pru_bind
  analysis (§6), and TCP disconnect race (§7).
- **OnePS postmortem:** `github.com/thebelx/OnePS` — SSV negatives and
  the pru_bind refutation.
- **Fahrenheit repo:** `github.com/thebelx/Fahrenheight` — currently
  404.
- **Test image tooling:** `fahrenheit.ps1`, UFS2Tool for base image
  creation. Instructions in the accompanying diag document.
