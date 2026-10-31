#pragma once

// Phoenix build-time feature toggles.
// Flip 0/1 to enable/disable checks and detections. Rebuild driver AND client
// after any change here (shared.hpp includes this on both sides).

// ------------------------------------------------------------------
// Master environment switch
// ------------------------------------------------------------------
// KG_ENV_LOCAL=1 -> agent, updater, driver, backend all point at 127.0.0.1
// KG_ENV_LOCAL=0 -> production hosts
// Setting to 1 also auto-forces KG_REQUIRE_UPDATER_GATE=0 so the agent can be
// launched directly without going through the updater.
#ifndef KG_ENV_LOCAL
#define KG_ENV_LOCAL 0
#endif

#if KG_ENV_LOCAL
#define KG_BACKEND_HOST_STR  "127.0.0.1"
#define KG_BACKEND_PORT_STR  "27015"
#define KG_UPDATER_HOST_STR  "127.0.0.1"
#define KG_UPDATER_PORT_STR  "27017"
#else
#define KG_BACKEND_HOST_STR  "REDACTED"
#define KG_BACKEND_PORT_STR  "27015"
#define KG_UPDATER_HOST_STR  "REDACTED"
#define KG_UPDATER_PORT_STR  "27017"
#endif

// ------------------------------------------------------------------
// Driver: handle protection
// ------------------------------------------------------------------
// Strip PROCESS_TERMINATE / VM_READ / VM_WRITE / etc. from handles opened
// against trusted processes. Blocks Task Manager kills, ReadProcessMemory,
// WriteProcessMemory, CreateRemoteThread against the game / worker.
#ifndef KG_ENFORCE_HANDLE_STRIP
#define KG_ENFORCE_HANDLE_STRIP 1
#endif

// ------------------------------------------------------------------
// Driver: environment posture
// ------------------------------------------------------------------
// Reject virtual machines (VMware / VirtualBox / Hyper-V / KVM).
// Detects via CPUID hypervisor bit + SMBIOS strings.
#ifndef KG_VM_ENFORCE
#define KG_VM_ENFORCE 1
#endif

// Require UEFI SecureBoot and HVCI (Memory Integrity) to arm.
// Users without both get rejected.
#ifndef KG_POSTURE_ENFORCE
#define KG_POSTURE_ENFORCE 1
#endif

// Refuse to load / launch when Windows boot config is insecure:
// kernel debugging on, testsigning on, or code integrity disabled.
// Flip to 0 for dev machines running a test-signed driver.
#ifndef KG_ENFORCE_SECURE_BOOTMODE
#define KG_ENFORCE_SECURE_BOOTMODE 1
#endif

// ------------------------------------------------------------------
// Driver: blocklist enforcement
// ------------------------------------------------------------------
// When set to 1, matched RE tools (WinDbg / x64dbg / IDA / Cheat Engine /
// Process Hacker / etc.) are RECORDED and reported via detection webhook
// but NOT terminated. Use only for kernel debug sessions. Ship as 0.
#if KG_ENV_LOCAL
#undef  KG_BLOCKLIST_REPORT_ONLY
#define KG_BLOCKLIST_REPORT_ONLY 1
#endif

#ifndef KG_BLOCKLIST_REPORT_ONLY
#define KG_BLOCKLIST_REPORT_ONLY 0
#endif

// ------------------------------------------------------------------
// Driver: blocklist master switch
// ------------------------------------------------------------------
// When set to 0, the RE-tool blocklist is entirely disabled: no image
// matching at process creation, no icon-hash scanning, no periodic
// sweep. Nothing gets recorded, nothing gets denied. Ship as 1.
#ifndef KG_BLOCKLIST_ENABLE
#define KG_BLOCKLIST_ENABLE 1
#endif

// ------------------------------------------------------------------
// Driver: vulnerable-driver scanner
// ------------------------------------------------------------------
// When set to 0, LoadImage notifications for kernel modules skip the
// MD5 blacklist check (RTCore64 / GIGABYTE / etc.). Ship as 1.
#ifndef KG_BLOCKDRV_ENABLE
#define KG_BLOCKDRV_ENABLE 1
#endif

// ------------------------------------------------------------------
// Driver: registry filter enforcement
// ------------------------------------------------------------------
// When set to 1, RegFilter denies writes that would create a new kernel
// driver service (blocks DebugView/Sysinternals/other tools that install
// helper drivers). When set to 0, RegFilter only observes/logs, allowing
// dev tools like DebugView (dbgv.sys), Process Explorer, WinDbg, etc.
// to install their drivers. Ship as 1.
#ifndef KG_REGFILTER_ENFORCE
#define KG_REGFILTER_ENFORCE 1
#endif

// ------------------------------------------------------------------
// Client (user-mode agent): anti-debug kill on window match
// ------------------------------------------------------------------
// When set to 1, a debugger-window hit (IDA/x64dbg/Cheat Engine window
// titles/classes seen via EnumWindows) closes the agent, which cascades
// KillAllTrusted in the kernel and takes the game down. When set to 0,
// the detection is still fired to the backend but the agent stays alive.
// Ship as 1.
#ifndef KG_ADBG_KILL_ON_WINDOW
#define KG_ADBG_KILL_ON_WINDOW 1
#endif

// ------------------------------------------------------------------
// Client (user-mode agent): anti-debug kill on ANY hit
// ------------------------------------------------------------------
// Master switch for all anti-debug enforcement. When set to 0, no
// anti-debug hit (peb, ntglobalflag, rdtsc, kernel-debugger, debugger-
// module, hw-breakpoint, etc.) will close the agent. Detections still
// get fired to the backend so the dashboard sees them, but the local
// process stays alive and FiveM is not cascaded. Ship as 1.
#ifndef KG_ADBG_KILL
#define KG_ADBG_KILL 1
#endif

// ------------------------------------------------------------------
// Client (user-mode agent): pointer encryption (ms_pInstance VEH)
// ------------------------------------------------------------------
// Master switch for the ptrcrypt subsystem. When 0, PtrCryptStart is
// never called and the game runs with no VEH overhead. Flip to 1 once
// a cold-pointer target is wired so the FPS cost stays negligible.
#ifndef KG_PTRCRYPT_ENABLE
#define KG_PTRCRYPT_ENABLE 0
#endif

// ------------------------------------------------------------------
// Client (user-mode agent): diagnostics
// ------------------------------------------------------------------
// Show console window + print lazy-import resolutions. Off in production.
#ifndef KG_LI_TRACE
#define KG_LI_TRACE 0
#endif

// ------------------------------------------------------------------
// Client (user-mode agent): updater gate
// ------------------------------------------------------------------
// Require the Updater to set PHOENIX_UPDATER_GATE before PhoenixAgent runs.
// Ship as 1 for production so direct launches of PhoenixAgent.exe are refused
// and only Updater-launched sessions are allowed. Flip to 0 for local dev
// so PhoenixAgent can run standalone without going through the Updater.
#if KG_ENV_LOCAL
#undef  KG_REQUIRE_UPDATER_GATE
#define KG_REQUIRE_UPDATER_GATE 0
#endif

#ifndef KG_REQUIRE_UPDATER_GATE
#define KG_REQUIRE_UPDATER_GATE 1
#endif

// ------------------------------------------------------------------
// Driver: kernel debug prints
// ------------------------------------------------------------------
// Emit DbgPrintEx traces for driver-side events. Visible in DebugView or a
// kernel debugger. Compile out with 0 for a silent .sys.
#ifndef KG_DRV_DEBUG_LOG
#define KG_DRV_DEBUG_LOG 0
#endif

// ------------------------------------------------------------------
// Client (user-mode agent): netmon debug prints
// ------------------------------------------------------------------
// Emit OutputDebugStringA traces for every TCP connect/accept, every
// DNS query, every HTTP URL, and every cheat-host match. Visible in
// DebugView (Capture Global Win32). Ship as 0 for a silent agent.
#ifndef KG_NETMON_DEBUG_LOG
#define KG_NETMON_DEBUG_LOG 0
#endif

#if defined(__clang__)
#define KG_NO_OBFUSCATE __attribute__((annotate("noirobf-cff")))
#else
#define KG_NO_OBFUSCATE
#endif
