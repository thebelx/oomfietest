// ps4_offsets.js — firmware offset table.
//
// 13.02 is the only entry fn_leak.js and the oomfie PoC actually consume.
// The WebKit gadget offsets are shared with 13.00 (Sony did not update
// WebKit between 13.00 and 13.02). The kernel RVAs are 13.02-specific.
//
// If you port to another firmware: replace the constants in that entry.
// The mapping of keys to sources in the original slopkit table is:
//
//   wk_expm1_builtin              JSFunction call target for Math.expm1
//   wk_JSFunction_m_function      offset of m_function in a JSFunction
//   wk_<gadget>_*                 WebKit text gadget offsets
//   wk_ArrayBuffer_m_impl         ArrayBuffer->m_impl offset
//   wk_ArrayBuffer_m_contents_m_data
//                                 ArrayBuffer->m_contents_m_data offset
//   k__error                      libkernel's errno location
//   k_kl_lock                     kqueue lock RVA for kernel base derivation
//   k_sysent_661                  sysent[661] RVA
//   k_jmp_rsi                     jmp rsi gadget in kernel text
//   k_stubs                       syscall stub table (id -> RVA)
//   allproc                       RVA of the process list head
//
// NOTE: this table does NOT include a working `allproc` value. The
// slopkit-derived 0x01CA8538 correction has been independently claimed
// but not re-verified on 13.02 in this project. Verify against your own
// dump before trusting it. The fn_leak walk will silently fail with
// "proc not found" if the RVA is wrong.

export const REQUIRED_KEYS = [
    "wk_expm1_builtin", "wk_JSFunction_m_function",
    "wk_POP_RDI_RET", "wk_POP_RSI_RET", "wk_POP_RDX_RET", "wk_POP_RCX_RET",
    "wk_POP_R8_RET", "wk_POP_R9_RET", "wk_POP_RAX_RET", "wk_LEAVE_RET",
    "wk_MOV_QWORD_PTR_RDI_RAX_RET",
    "wk_MOV_RDI_RSI_30_CALL", "wk_POP_RAX_MOV_RAX_JMP_18",
    "wk_PUSH_RBP_MOV_RBP_RSP_10", "wk_MOV_RDI_RAX_8_CALL_20",
    "wk_MOV_RDX_RAX_18_CALL_10", "wk_PUSH_RDX_POP_RSP_RET",
    "pivot_view_sp",
    "wk_ArrayBuffer_m_impl", "wk_ArrayBuffer_m_contents_m_data",
    "wk___imp___error", "k__error",
    "k_kl_lock", "k_sysent_661", "k_jmp_rsi",
];

export const OPTIONAL_KEYS = [
    "k_stubs", "allproc",
];

function _stub(ver, note) {
    return {
        fw_status: "state=INCOMPLETE " + note,
        wk_expm1_builtin:                 0xDEADBEEF,
        wk_JSFunction_m_function:         0x28,
        wk_POP_RDI_RET:                   0xDEAD0001,
        wk_POP_RSI_RET:                   0xDEAD0002,
        wk_POP_RDX_RET:                   0xDEAD0003,
        wk_POP_RCX_RET:                   0xDEAD0004,
        wk_POP_R8_RET:                    0xDEAD0006,
        wk_POP_R9_RET:                    0xDEAD0007,
        wk_POP_RAX_RET:                   0xDEAD0005,
        wk_LEAVE_RET:                     0xDEAD0008,
        wk_MOV_QWORD_PTR_RDI_RAX_RET:     0xDEAD0009,
        wk_PUSH_RDX_POP_RSP_RET:          0xDEAD000A,
        wk_MOV_RDI_RSI_30_CALL:           0xDEAD000B,
        wk_POP_RAX_MOV_RAX_JMP_18:        0xDEAD000C,
        wk_PUSH_RBP_MOV_RBP_RSP_10:       0xDEAD000D,
        wk_MOV_RDI_RAX_8_CALL_20:         0xDEAD000E,
        wk_MOV_RDX_RAX_18_CALL_10:        0xDEAD000F,
        pivot_view_sp:                    0x18,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk___imp___error:                 0xDEAD0010,
        k__error:                         0xDEAD0011,
        k_kl_lock:                        0,
        k_sysent_661:                     0x110a760,
        k_jmp_rsi:                        0xDEAD0201,
        allproc:                          0,
        k_stubs: {},
    };
}

export const PS4 = {

// ═══════════════════════════════════════════════════════════════════════
// 13.02
//
// WebKit offsets are identical to 13.00 (Sony did not relink the WebKit
// module between those firmwares). Kernel RVAs are 13.02-specific and
// came from a public 13.02 kernel dump.
//
// k_kl_lock and k_sysent_661 are verified against the 13.02 dump. allproc
// is not — see note at the top of the file.
// ═══════════════════════════════════════════════════════════════════════
"13.02": {
    fw_status: "state=partial " +
        "webkit=shared-with-13.00 " +
        "kernel_rvas=verified-against-dump-except-allproc",

    // WebKit — engine text gadgets and structure offsets
    wk_expm1_builtin:                   0x2586880,
    wk_JSFunction_m_function:           0x28,

    wk_POP_RDI_RET:                     0x5c480,
    wk_POP_RSI_RET:                     0x6e45e,
    wk_POP_RDX_RET:                     0x12c5ba,
    wk_POP_RCX_RET:                     0x1bade,
    wk_POP_RAX_RET:                     0x10504,
    wk_POP_R8_RET:                      0x9b311,
    wk_POP_R9_RET:                      0x1dcfb1,
    wk_LEAVE_RET:                       0x182f7,
    wk_MOV_QWORD_PTR_RDI_RAX_RET:       0x548b,
    wk_PUSH_RDX_POP_RSP_RET:            0x2abccaa,
    wk_MOV_RDI_RSI_30_CALL:             0x295f948,
    wk_POP_RAX_MOV_RAX_JMP_18:          0x1d989e3,
    wk_PUSH_RBP_MOV_RBP_RSP_10:         0x25bae0,
    wk_MOV_RDI_RAX_8_CALL_20:           0x4a0406,
    wk_MOV_RDX_RAX_18_CALL_10:          0x1ec3ada,

    pivot_view_sp:                      0x38,
    wk_ArrayBuffer_m_impl:              0x10,
    wk_ArrayBuffer_m_contents_m_data:   0x10,

    // WebKit anchor and libkernel derivation
    wk___imp___error:                   0x3cb8cc8,
    k__error:                           0x26420,

    // Kernel
    k_kl_lock:                          0xe6c20,
    k_sysent_661:                       0x110a760,
    k_jmp_rsi:                          0x47b31,

    // UNVERIFIED in this project. See file-header note.
    allproc:                            0x01CA8538,

    // libkernel syscall stubs. Populated at runtime by fn_leak.js's
    // stub scanner if the RVAs drift; k_stubs is only a starting hint.
    k_stubs: {
        3:   0x2c170,
        4:   0x2b8d0,
        5:   0x2b970,
        6:   0x2d620,
        20:  0x2cb70,
        23:  0x2b6f0,
        24:  0x2d5e0,
        25:  0x2b4d0,
        30:  0x2c9d0,
        54:  0x2cff0,
        92:  0x2b650,
        97:  0x2d050,
        98:  0x2b5f0,
        104: 0x2d380,
        105: 0x2b490,
        106: 0x2d480,
        118: 0x2b2f0,
        135: 0x2c280,
        240: 0x2d4c0,
        331: 0x2c6b0,
        432: 0x2b510,
        466: 0x2cc70,
        487: 0x2ba80,
        488: 0x2bd10,
        538: 0x2b430,
        539: 0x2b4f0,
        544: 0x2beb0,
        545: 0x2ca30,
        632: 0x2d090,
        633: 0x2d840,
        662: 0x2ccb0,
        663: 0x2c3e0,
        664: 0x2d740,
        666: 0x2d540,
        669: 0x2bdf0,
    },
},

// ═══════════════════════════════════════════════════════════════════════
// Placeholder entries for the firmware range the original slopkit table
// covers. Untested by this project. Kept so the firmware matcher below
// doesn't fail on any PS4 that hits this file.
// ═══════════════════════════════════════════════════════════════════════
"9.00":  _stub("9.00",  "webkit=NEEDS-DUMP kernel_rvas=community-verified"),
"11.00": _stub("11.00", "webkit=NEEDS-DUMP kernel_rvas=UNTESTED"),
"11.50": _stub("11.50", "webkit=NEEDS-DUMP kernel_rvas=UNTESTED"),
"12.00": _stub("12.00", "webkit=NEEDS-DUMP kernel_rvas=UNTESTED"),
"12.50": _stub("12.50", "webkit=NEEDS-DUMP kernel_rvas=UNTESTED"),
"13.00": _stub("13.00", "webkit=NEEDS-DUMP kernel_rvas=UNTESTED"),

};

// Aliases — keep the table lookup from returning null on firmware that
// shares a sibling's layout. All marked with alias_of so callers can see
// the value is inherited, not verified.
PS4["9.03"]  = Object.assign({}, PS4["9.00"],  { alias_of: "9.00"  });
PS4["9.04"]  = Object.assign({}, PS4["9.00"],  { alias_of: "9.00"  });
PS4["11.52"] = Object.assign({}, PS4["11.50"], { alias_of: "11.50" });
PS4["12.02"] = Object.assign({}, PS4["12.00"], { alias_of: "12.00" });
PS4["12.52"] = Object.assign({}, PS4["12.50"], { alias_of: "12.50" });

// 13.04, 13.50, 13.52 — no verified table. Left as stubs so a direct
// URL hit on one of those returns a clean "no offsets" rather than
// crashing inside establishPrimitive.
PS4["13.04"] = _stub("13.04", "webkit=NEEDS-DUMP kernel_rvas=UNVERIFIED");
PS4["13.50"] = _stub("13.50", "webkit=NEEDS-DUMP kernel_rvas=UNVERIFIED");
PS4["13.52"] = _stub("13.52", "webkit=NEEDS-DUMP kernel_rvas=UNVERIFIED");

// ═══════════════════════════════════════════════════════════════════════
// Firmware matcher.
//
// PS4 user-agent formats seen in the wild:
//   Mozilla/5.0 (PlayStation 4 13.02) AppleWebKit/...
//   Mozilla/5.0 (PlayStation 4/13.02) AppleWebKit/...
// Minor version is decimal on PS4 (unlike PS3, which used hex).
// ═══════════════════════════════════════════════════════════════════════

export function offsetsFor(uaString) {
    const m = (uaString || "").match(/PlayStation\s*4[\/ ](\d+)\.(\d+)/);
    if (!m) return { key: null, off: null };

    const major = m[1];
    const minor = m[2].padStart(2, "0");
    const key = major + "." + minor;

    const off = PS4[key]
        || PS4[major + "." + minor.replace(/0$/, "")]
        || null;

    return { key, off };
}

export default { PS4, offsetsFor };