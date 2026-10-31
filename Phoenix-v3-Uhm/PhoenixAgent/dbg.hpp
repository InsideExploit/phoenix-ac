#pragma once
#include <stdio.h>
#include <windows.h>
#include "shared.hpp"
#include "pxstr.hpp"

#if defined(KG_DEBUG) || KG_LI_TRACE
#define KGDBG(fmt, ...) do { wprintf(PX_WS(L"[PhoenixAC] " fmt), ##__VA_ARGS__); fflush(stdout); } while (0)
#else
#define KGDBG(...) ((void)0)
#endif

#if KG_LI_TRACE
static inline void KgAttachConsoleOnce(void) {
    static LONG done = 0;
    if (InterlockedCompareExchange(&done, 1, 0) != 0) return;
    AllocConsole();
    FILE* fout = NULL;
    FILE* ferr = NULL;
    freopen_s(&fout, "CONOUT$", "w", stdout);
    freopen_s(&ferr, "CONOUT$", "w", stderr);
    SetConsoleTitleW(L"PhoenixAgent Debug");
}
#else
static inline void KgAttachConsoleOnce(void) {}
#endif
