#include "sigcheck.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <string.h>
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define SIG_SERIAL_HEX_MAX 129

LONG
SigVerifyTrust(
    const wchar_t* Path
)
{
    if (!Path || !*Path)
        return TRUST_E_NOSIGNATURE;

    GUID actionV2 = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_FILE_INFO fi = { 0 };
    fi.cbStruct       = sizeof(fi);
    fi.pcwszFilePath  = Path;
    fi.hFile          = NULL;
    fi.pgKnownSubject = NULL;

    WINTRUST_DATA wd = { 0 };
    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fi;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG rc = LI_WINTRUST(WinVerifyTrust)((HWND)INVALID_HANDLE_VALUE, &actionV2, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    LI_WINTRUST(WinVerifyTrust)((HWND)INVALID_HANDLE_VALUE, &actionV2, &wd);

    return rc;
}

bool
SigGetSignerSerialHex(
    const wchar_t* Path,
    char*          Out,
    size_t         OutCap
)
{
    BRKIDA;

    if (!Path || !*Path || !Out || OutCap == 0)
        return false;

    Out[0] = 0;

    DWORD       encoding    = 0;
    DWORD       contentType = 0;
    DWORD       formatType  = 0;
    HCERTSTORE  store       = NULL;
    HCRYPTMSG   msg         = NULL;

    if (!LI_CRYPT32(CryptQueryObject)(
            CERT_QUERY_OBJECT_FILE,
            Path,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &encoding, &contentType, &formatType,
            &store, &msg, NULL))
        return false;

    bool  ok    = false;
    DWORD siLen = 0;

    if (msg && LI_CRYPT32(CryptMsgGetParam)(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &siLen) && siLen) {
        CMSG_SIGNER_INFO* si = (CMSG_SIGNER_INFO*)HeapAlloc(GetProcessHeap(), 0, siLen);
        if (si) {
            if (LI_CRYPT32(CryptMsgGetParam)(msg, CMSG_SIGNER_INFO_PARAM, 0, si, &siLen)) {
                CERT_INFO ci = { 0 };
                ci.Issuer       = si->Issuer;
                ci.SerialNumber = si->SerialNumber;

                PCCERT_CONTEXT ctx = LI_CRYPT32(CertFindCertificateInStore)(
                    store, encoding, 0, CERT_FIND_SUBJECT_CERT, &ci, NULL);

                if (ctx) {
                    const CRYPT_INTEGER_BLOB* sn = &ctx->pCertInfo->SerialNumber;

                    DWORD n = sn->cbData;
                    while (n > 1 && sn->pbData[n - 1] == 0)
                        --n;

                    if (n > 0 && (size_t)n * 2 + 1 <= OutCap) {
                        static const char hd[] = "0123456789abcdef";
                        size_t o = 0;
                        for (DWORD i = n; i > 0; --i) {
                            BYTE b = sn->pbData[i - 1];
                            Out[o++] = hd[(b >> 4) & 0x0F];
                            Out[o++] = hd[b & 0x0F];
                        }
                        Out[o] = 0;
                        ok = true;
                    }

                    LI_CRYPT32(CertFreeCertificateContext)(ctx);
                }
            }
            HeapFree(GetProcessHeap(), 0, si);
        }
    }

    if (msg)   LI_CRYPT32(CryptMsgClose)(msg);
    if (store) LI_CRYPT32(CertCloseStore)(store, 0);

    return ok;
}

bool
SigIsTrustedWithSerial(
    const wchar_t* Path,
    const char*    ExpectedSerialHex
)
{
    BRKIDA;

    if (!Path || !*Path || !ExpectedSerialHex || !*ExpectedSerialHex)
        return false;

    LONG rc = SigVerifyTrust(Path);
    if (rc != ERROR_SUCCESS) {
        KGDBG(L"[sigcheck] untrusted %ls rc=0x%08lx\n", Path, (unsigned long)rc);
        return false;
    }

    char serial[SIG_SERIAL_HEX_MAX] = { 0 };
    if (!SigGetSignerSerialHex(Path, serial, sizeof(serial))) {
        KGDBG(L"[sigcheck] serial unreadable %ls\n", Path);
        return false;
    }

    if (_stricmp(serial, ExpectedSerialHex) != 0) {
        KGDBG(L"[sigcheck] serial mismatch %ls got=%hs\n", Path, serial);
        return false;
    }

    return true;
}
