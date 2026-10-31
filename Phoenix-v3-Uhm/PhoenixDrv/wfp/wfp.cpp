#include "wfp.hpp"

#define INITGUID
#include <ntifs.h>
#include <initguid.h>

#define NDIS_SUPPORT_NDIS6 1
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>

#include "shared.hpp"
#include "klazy.hpp"
#include "pxstr.hpp"

#include "integrity/integrity.hpp"

#pragma comment(lib, "netio.lib")

DEFINE_GUID(KG_WFP_SUBLAYER,
    0x9c4e6a1d, 0x2b83, 0x4f76, 0xa8, 0x21, 0x6d, 0xef, 0x33, 0x91, 0x55, 0x0c);

DEFINE_GUID(KG_WFP_CALLOUT_V4_CONNECT,
    0x9c4e6a1d, 0x2b83, 0x4f76, 0xa8, 0x21, 0x6d, 0xef, 0x33, 0x91, 0x55, 0x0d);
DEFINE_GUID(KG_WFP_CALLOUT_V6_CONNECT,
    0x9c4e6a1d, 0x2b83, 0x4f76, 0xa8, 0x21, 0x6d, 0xef, 0x33, 0x91, 0x55, 0x0e);
DEFINE_GUID(KG_WFP_CALLOUT_V4_ACCEPT,
    0x9c4e6a1d, 0x2b83, 0x4f76, 0xa8, 0x21, 0x6d, 0xef, 0x33, 0x91, 0x55, 0x0f);
DEFINE_GUID(KG_WFP_CALLOUT_V6_ACCEPT,
    0x9c4e6a1d, 0x2b83, 0x4f76, 0xa8, 0x21, 0x6d, 0xef, 0x33, 0x91, 0x55, 0x10);

#define KG_NETMON_RING_SIZE 512

static HANDLE          g_EngineHandle = NULL;
static PDEVICE_OBJECT  g_NetmonDevice = NULL;
static UINT32          g_CalloutIdV4C = 0;
static UINT32          g_CalloutIdV6C = 0;
static UINT32          g_CalloutIdV4A = 0;
static UINT32          g_CalloutIdV6A = 0;
static KSPIN_LOCK      g_RingLock;
static KG_NET_EVENT    g_Ring[KG_NETMON_RING_SIZE];
static ULONG           g_RingHead = 0;
static ULONG           g_RingTail = 0;

KG_NO_OBFUSCATE
static
VOID
PushEvent(
    _In_ const KG_NET_EVENT* Ev
)
{
    KIRQL OldIrql;
    OldIrql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_RingLock);

    g_Ring[g_RingHead] = *Ev;
    g_RingHead = (g_RingHead + 1) % KG_NETMON_RING_SIZE;
    if (g_RingHead == g_RingTail)
        g_RingTail = (g_RingTail + 1) % KG_NETMON_RING_SIZE;

    g_KH.KeReleaseSpinLock(&g_RingLock, OldIrql);
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
NetmonPop(
    PVOID   OutBuf,
    ULONG   OutCap,
    PULONG  BytesReturned
)
{
    *BytesReturned = 0;

    if (OutCap < sizeof(KG_NET_EVENT))
        return STATUS_BUFFER_TOO_SMALL;

    KIRQL OldIrql;
    OldIrql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_RingLock);

    if (g_RingHead == g_RingTail) {
        g_KH.KeReleaseSpinLock(&g_RingLock, OldIrql);
        return STATUS_NO_MORE_ENTRIES;
    }

    RtlCopyMemory(OutBuf, &g_Ring[g_RingTail], sizeof(KG_NET_EVENT));
    g_RingTail = (g_RingTail + 1) % KG_NETMON_RING_SIZE;

    g_KH.KeReleaseSpinLock(&g_RingLock, OldIrql);

    *BytesReturned = sizeof(KG_NET_EVENT);
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
static
VOID
NTAPI
ClassifyTcp(
    _In_        const FWPS_INCOMING_VALUES*           InFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES*  InMetaValues,
    _Inout_opt_ VOID*                                 LayerData,
    _In_opt_    const VOID*                           ClassifyContext,
    _In_        const FWPS_FILTER*                    Filter,
    _In_        UINT64                                FlowContext,
    _Inout_     FWPS_CLASSIFY_OUT*                    ClassifyOut
)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    if (ClassifyOut != NULL) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
            return;
    }

    KG_NET_EVENT Event = { 0 };

    LARGE_INTEGER Timestamp;
    KL_NT(KeQuerySystemTimePrecise)(&Timestamp);
    Event.TimestampMs = (UINT64)(Timestamp.QuadPart / 10000);

    HANDLE Pid = 0;
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
        Pid = (HANDLE)(ULONG_PTR)InMetaValues->processId;

    Event.Pid = (UINT32)(ULONG_PTR)Pid;

    Event.Family = InFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4 ||
                   InFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4
                 ? (UINT16)AF_INET : (UINT16)AF_INET6;

    bool IsConnect = (InFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4 ||
                      InFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6);
    Event.Kind = IsConnect ? KG_NETEVT_TCP_CONNECT : KG_NETEVT_TCP_ACCEPT;

    if (Event.Family == AF_INET) {
        UINT32 LocalV4 = InFixedValues->incomingValue[IsConnect
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS
            : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
        UINT32 RemoteV4 = InFixedValues->incomingValue[IsConnect
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS
            : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
        UINT16 LocalPort = InFixedValues->incomingValue[IsConnect
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT
            : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
        UINT16 RemotePort = InFixedValues->incomingValue[IsConnect
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT
            : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;

        Event.LocalAddr[0]  = (UINT8)(LocalV4 >> 24);
        Event.LocalAddr[1]  = (UINT8)(LocalV4 >> 16);
        Event.LocalAddr[2]  = (UINT8)(LocalV4 >> 8);
        Event.LocalAddr[3]  = (UINT8)LocalV4;
        Event.RemoteAddr[0] = (UINT8)(RemoteV4 >> 24);
        Event.RemoteAddr[1] = (UINT8)(RemoteV4 >> 16);
        Event.RemoteAddr[2] = (UINT8)(RemoteV4 >> 8);
        Event.RemoteAddr[3] = (UINT8)RemoteV4;
        Event.LocalPort     = LocalPort;
        Event.RemotePort    = RemotePort;
    } else {
        FWP_BYTE_ARRAY16* LocalV6 = InFixedValues->incomingValue[IsConnect
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS
            : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.byteArray16;
        FWP_BYTE_ARRAY16* RemoteV6 = InFixedValues->incomingValue[IsConnect
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS
            : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        UINT16 LocalPort = InFixedValues->incomingValue[IsConnect
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT
            : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
        UINT16 RemotePort = InFixedValues->incomingValue[IsConnect
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT
            : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16;

        if (LocalV6 != NULL)
            RtlCopyMemory(Event.LocalAddr,  LocalV6->byteArray16,  16);
        if (RemoteV6 != NULL)
            RtlCopyMemory(Event.RemoteAddr, RemoteV6->byteArray16, 16);

        Event.LocalPort  = LocalPort;
        Event.RemotePort = RemotePort;
    }

    Event.ProcessPath[0] = 0;
    Event.ProcessPathLen = 0;
    PushEvent(&Event);
}

KG_NO_OBFUSCATE
static
NTSTATUS
NTAPI
NotifyStub(
    _In_    FWPS_CALLOUT_NOTIFY_TYPE  NotifyType,
    _In_    const GUID*               FilterKey,
    _Inout_ FWPS_FILTER*              Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

static
NTSTATUS
AddCallout(
    _In_  PDEVICE_OBJECT DeviceObject,
    _In_  const GUID*    CalloutKey,
    _In_  const GUID*    LayerKey,
    _Out_ UINT32*        Id
)
{
    FWPS_CALLOUT Callout = { 0 };
    Callout.calloutKey   = *CalloutKey;
    Callout.classifyFn   = ClassifyTcp;
    Callout.notifyFn     = NotifyStub;
    Callout.flowDeleteFn = NULL;

    NTSTATUS Status = KL_FWPK(FwpsCalloutRegister3)(DeviceObject, &Callout, Id);
    if (!NT_SUCCESS(Status))
        return Status;

    FWPM_CALLOUT MgmtCallout    = { 0 };
    MgmtCallout.calloutKey      = *CalloutKey;
    MgmtCallout.applicableLayer = *LayerKey;

    FWPM_DISPLAY_DATA DisplayData = {
        const_cast<PWSTR>(PX_W(L"PhoenixDrv")),
        const_cast<PWSTR>(PX_W(L""))
    };
    MgmtCallout.displayData = DisplayData;

    Status = KL_FWPK(FwpmCalloutAdd0)(g_EngineHandle, &MgmtCallout, NULL, NULL);
    if (!NT_SUCCESS(Status) && Status != STATUS_FWP_ALREADY_EXISTS) {
        KL_FWPK(FwpsCalloutUnregisterById0)(*Id);
        *Id = 0;
        return Status;
    }

    FWPM_FILTER Filter        = { 0 };
    Filter.layerKey           = *LayerKey;
    Filter.subLayerKey        = KG_WFP_SUBLAYER;
    Filter.action.type        = FWP_ACTION_CALLOUT_INSPECTION;
    Filter.action.calloutKey  = *CalloutKey;
    Filter.weight.type        = FWP_EMPTY;

    FWPM_DISPLAY_DATA FilterDisplay = {
        const_cast<PWSTR>(PX_W(L"PhoenixDrv")),
        const_cast<PWSTR>(PX_W(L""))
    };
    Filter.displayData = FilterDisplay;

    return KL_FWPK(FwpmFilterAdd0)(g_EngineHandle, &Filter, NULL, NULL);
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
WfpInstall(
    PDRIVER_OBJECT Driver
)
{
    PAGED_CODE();

    KL_NT(KeInitializeSpinLock)(&g_RingLock);
    g_RingHead = 0;
    g_RingTail = 0;

    UNICODE_STRING DeviceName;
    KlazyMakeUS(&DeviceName, PX_W(L"\\Device\\PhoenixDrvNetmon"));

    NTSTATUS Status = KL_NT(IoCreateDevice)(Driver,
                                            0,
                                            &DeviceName,
                                            FILE_DEVICE_UNKNOWN,
                                            0,
                                            FALSE,
                                            &g_NetmonDevice);
    if (!NT_SUCCESS(Status))
        return Status;

    FWPM_SESSION Session = { 0 };
    Session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    Status = KL_FWPK(FwpmEngineOpen0)(NULL, RPC_C_AUTHN_WINNT, NULL, &Session, &g_EngineHandle);
    if (!NT_SUCCESS(Status)) {
        KL_NT(IoDeleteDevice)(g_NetmonDevice);
        g_NetmonDevice = NULL;
        return Status;
    }

    Status = KL_FWPK(FwpmTransactionBegin0)(g_EngineHandle, 0);
    if (!NT_SUCCESS(Status)) {
        KL_FWPK(FwpmEngineClose0)(g_EngineHandle);
        g_EngineHandle = NULL;
        KL_NT(IoDeleteDevice)(g_NetmonDevice);
        g_NetmonDevice = NULL;
        return Status;
    }

    FWPM_SUBLAYER SubLayer = { 0 };
    SubLayer.subLayerKey   = KG_WFP_SUBLAYER;

    FWPM_DISPLAY_DATA SubLayerDisplay = {
        const_cast<PWSTR>(PX_W(L"PhoenixDrv")),
        const_cast<PWSTR>(PX_W(L""))
    };
    SubLayer.displayData = SubLayerDisplay;
    SubLayer.weight      = 0x8000;

    Status = KL_FWPK(FwpmSubLayerAdd0)(g_EngineHandle, &SubLayer, NULL);
    if (!NT_SUCCESS(Status) && Status != STATUS_FWP_ALREADY_EXISTS)
        goto Fail;

    Status = AddCallout(g_NetmonDevice,
                        &KG_WFP_CALLOUT_V4_CONNECT,
                        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        &g_CalloutIdV4C);
    if (!NT_SUCCESS(Status))
        goto Fail;

    Status = AddCallout(g_NetmonDevice,
                        &KG_WFP_CALLOUT_V6_CONNECT,
                        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        &g_CalloutIdV6C);
    if (!NT_SUCCESS(Status))
        goto Fail;

    Status = AddCallout(g_NetmonDevice,
                        &KG_WFP_CALLOUT_V4_ACCEPT,
                        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                        &g_CalloutIdV4A);
    if (!NT_SUCCESS(Status))
        goto Fail;

    Status = AddCallout(g_NetmonDevice,
                        &KG_WFP_CALLOUT_V6_ACCEPT,
                        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                        &g_CalloutIdV6A);
    if (!NT_SUCCESS(Status))
        goto Fail;

    Status = KL_FWPK(FwpmTransactionCommit0)(g_EngineHandle);
    if (!NT_SUCCESS(Status))
        goto Fail;

    IntegrityRegister((PVOID)&ClassifyTcp);
    return STATUS_SUCCESS;

Fail:
    KL_FWPK(FwpmTransactionAbort0)(g_EngineHandle);

    if (g_CalloutIdV4C) { KL_FWPK(FwpsCalloutUnregisterById0)(g_CalloutIdV4C); g_CalloutIdV4C = 0; }
    if (g_CalloutIdV6C) { KL_FWPK(FwpsCalloutUnregisterById0)(g_CalloutIdV6C); g_CalloutIdV6C = 0; }
    if (g_CalloutIdV4A) { KL_FWPK(FwpsCalloutUnregisterById0)(g_CalloutIdV4A); g_CalloutIdV4A = 0; }
    if (g_CalloutIdV6A) { KL_FWPK(FwpsCalloutUnregisterById0)(g_CalloutIdV6A); g_CalloutIdV6A = 0; }

    KL_FWPK(FwpmEngineClose0)(g_EngineHandle);
    g_EngineHandle = NULL;
    KL_NT(IoDeleteDevice)(g_NetmonDevice);
    g_NetmonDevice = NULL;
    return Status;
}

static
VOID
UnregisterCalloutWithRetry(
    _Inout_ UINT32* Id
)
{
    if (*Id == 0)
        return;

    for (int Retry = 0; Retry < 50; Retry++) {
        NTSTATUS Status = KL_FWPK(FwpsCalloutUnregisterById0)(*Id);
        if (Status != STATUS_DEVICE_BUSY)
            break;

        LARGE_INTEGER Delay;
        Delay.QuadPart = -100 * 10000LL;
        KL_NT(KeDelayExecutionThread)(KernelMode, FALSE, &Delay);
    }

    *Id = 0;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
WfpUninstall(
    VOID
)
{
    PAGED_CODE();

    if (g_EngineHandle != NULL) {
        KL_FWPK(FwpmEngineClose0)(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    UnregisterCalloutWithRetry(&g_CalloutIdV4C);
    UnregisterCalloutWithRetry(&g_CalloutIdV6C);
    UnregisterCalloutWithRetry(&g_CalloutIdV4A);
    UnregisterCalloutWithRetry(&g_CalloutIdV6A);

    if (g_NetmonDevice != NULL) {
        KL_NT(IoDeleteDevice)(g_NetmonDevice);
        g_NetmonDevice = NULL;
    }
}
