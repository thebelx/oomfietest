# Fahrenheit & oomfie

Two kernel findings on PS4 firmware 13.02.

**Fahrenheit** — unvalidated UFS superblocks in `ffs_mountfs`. A
missing field-relationship validator on 13.02 causes an undersized
allocation relative to the write loop's length. Reachable from external
media under unverified conditions.

**oomfie** — an unbounded stack write in `sys_ipmimgr` command 0.
Corrupts the identity fields of freshly-allocated `ConnectRequest`
objects. Identity collision leads to a use-after-free. Triggerable from
any process that can issue syscall 622.

Neither is a jailbreak. Both are components. Both are documented against
the public 13.02 kernel dump.

## Site

Live at: <https://thebelx.github.io/Fahrenheight/>

## PoCs

- `poc/setup_usb.sh` — builds a crafted UFS2 image for the Fahrenheit trigger
- `poc/ipmi_poc.js` — `sys_ipmimgr` trigger, for the `chain_poops` JS harness
- `poc/ipmi_poc.c` — same trigger, for a devkit or payload SDK

None of these have been tested on hardware. They may panic the kernel.

## License

Written analysis and PoC code are provided as-is, with no warranty.
Use on hardware you can afford to lose.