#include "token.hpp"
#include "pxstr.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

__declspec(noinline)
void
TokenToHex(
    const BYTE Token[KG_TOKEN_LEN],
    wchar_t    Out[KG_TOKEN_HEX_CHARS + 1]
)
{
    BRKIDA;
    auto digits   = PX_W(L"0123456789abcdef");
    volatile int   _vm_seal = 0;

    VIRTUALIZER_START
    for (int i = 0; i < KG_TOKEN_LEN; ++i) {
        Out[i * 2]     = digits[(Token[i] >> 4) & 0xF];
        Out[i * 2 + 1] = digits[ Token[i]       & 0xF];
    }
    Out[KG_TOKEN_HEX_CHARS] = L'\0';
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;
}

__declspec(noinline)
bool
HexToToken(
    const wchar_t* Hex,
    BYTE           Token[KG_TOKEN_LEN]
)
{
    BRKIDA;
    if (!Hex)
        return false;

    if (wcslen(Hex) != KG_TOKEN_HEX_CHARS)
        return false;

    bool         ok       = true;
    volatile int _vm_seal = 0;

    VIRTUALIZER_START
    for (int i = 0; i < KG_TOKEN_LEN && ok; ++i) {
        int     hi = -1, lo = -1;
        wchar_t ch = Hex[i * 2];
        if (ch >= L'0' && ch <= L'9')
            hi = ch - L'0';
        else if (ch >= L'a' && ch <= L'f')
            hi = 10 + (ch - L'a');
        else if (ch >= L'A' && ch <= L'F')
            hi = 10 + (ch - L'A');

        wchar_t cl = Hex[i * 2 + 1];
        if (cl >= L'0' && cl <= L'9')
            lo = cl - L'0';
        else if (cl >= L'a' && cl <= L'f')
            lo = 10 + (cl - L'a');
        else if (cl >= L'A' && cl <= L'F')
            lo = 10 + (cl - L'A');

        if (hi < 0 || lo < 0)
            ok = false;
        else
            Token[i] = (BYTE)((hi << 4) | lo);
    }
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;

    return ok;
}
