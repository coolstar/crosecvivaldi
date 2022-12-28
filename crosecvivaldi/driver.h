#if !defined(_CROSECVIVALDI_H_)
#define _CROSECVIVALDI_H_

#pragma warning(disable:4200)  // suppress nameless struct/union warning
#pragma warning(disable:4201)  // suppress nameless struct/union warning
#pragma warning(disable:4214)  // suppress bit field types other than int warning
#include <initguid.h>
#include <wdm.h>

#pragma warning(default:4200)
#pragma warning(default:4201)
#pragma warning(default:4214)
#include <wdf.h>

#include "crosecvivaldi.h"
#include <acpiioct.h>
#include <ntstrsafe.h>
#include <ntddkbd.h>

//
// String definitions
//

#define DRIVERNAME                 "crosecvivaldi.sys: "

#define CROSECVIVALDI_POOL_TAG            (ULONG) 'CRVD'
#define CROSECVIVALDI_HARDWARE_IDS        L"CoolStar\\GOOG0007\0\0"
#define CROSECVIVALDI_HARDWARE_IDS_LENGTH sizeof(CROSECVIVALDI_HARDWARE_IDS)

#define NTDEVICE_NAME_STRING       L"\\Device\\GOOG0007"
#define SYMBOLIC_NAME_STRING       L"\\DosDevices\\GOOG0007"

#define true 1
#define false 0

typedef struct _CROSEC_COMMAND {
    UINT32 Version;
    UINT32 Command;
    UINT32 OutSize;
    UINT32 InSize;
    UINT32 Result;
    UINT8 Data[];
} CROSEC_COMMAND, * PCROSEC_COMMAND;

typedef
NTSTATUS
(*PCROSEC_CMD_XFER_STATUS)(
    IN      PVOID Context,
    OUT     PCROSEC_COMMAND Msg
    );

typedef
BOOLEAN
(*PCROSEC_CHECK_FEATURES)(
    IN PVOID Context,
    IN INT Feature
    );

DEFINE_GUID(GUID_CROSEC_INTERFACE_STANDARD,
    0xd7062676, 0xe3a4, 0x11ec, 0xa6, 0xc4, 0x24, 0x4b, 0xfe, 0x99, 0x46, 0xd0);

/*DEFINE_GUID(GUID_DEVICE_PROPERTIES,
    0xdaffd814, 0x6eba, 0x4d8c, 0x8a, 0x91, 0xbc, 0x9b, 0xbf, 0x4a, 0xa3, 0x01);*/ //Windows defender false positive

    //
    // Interface for getting and setting power level etc.,
    //
typedef struct _CROSEC_INTERFACE_STANDARD {
    INTERFACE                        InterfaceHeader;
    PCROSEC_CMD_XFER_STATUS          CmdXferStatus;
    PCROSEC_CHECK_FEATURES           CheckFeatures;
} CROSEC_INTERFACE_STANDARD, * PCROSEC_INTERFACE_STANDARD;

typedef struct KeySetting {
    USHORT MakeCode;
    USHORT Flags;
} KeySetting, * PKeySetting;

typedef enum {
    CSVivaldiRequestEndpointRegister,
    CSVivaldiRequestLoadSettings
} CSVivaldiRequest;

typedef struct CSVivaldiSettingsArg {
    UINT32 argSz;
    CSVivaldiRequest settingsRequest;
    union args {
        struct {
            UINT8 functionRowCount;
            KeySetting functionRowKeys[16];
        } settings;
    } args;
} CSVivaldiSettingsArg, * PCSVivaldiSettingsArg;

typedef struct _CROSECVIVALDI_CONTEXT
{
    //
    // Handle back to the WDFDEVICE
    //

    WDFDEVICE FxDevice;

    PVOID CrosEcBusContext;

    PCROSEC_CMD_XFER_STATUS CrosEcCmdXferStatus;

    PCALLBACK_OBJECT CSSettingsCallback;
    PVOID CSSettingsCallbackObj;

    UINT8 functionRowCount;
    UINT8 functionRowKeys[16];

} CROSECVIVALDI_CONTEXT, * PCROSECVIVALDI_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(CROSECVIVALDI_CONTEXT, GetDeviceContext)

//
// Function definitions
//

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_UNLOAD CrosEcVivaldiDriverUnload;

EVT_WDF_DRIVER_DEVICE_ADD CrosEcVivaldiEvtDeviceAdd;

EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL CrosEcVivaldiEvtInternalDeviceControl;

//
// Helper macros
//

#define DEBUG_LEVEL_ERROR   1
#define DEBUG_LEVEL_INFO    2
#define DEBUG_LEVEL_VERBOSE 3

#define DBG_INIT  1
#define DBG_PNP   2
#define DBG_IOCTL 4

#if 0
#define CrosEcVivaldiPrint(dbglevel, dbgcatagory, fmt, ...) {          \
    if (CrosEcVivaldiDebugLevel >= dbglevel &&                         \
        (CrosEcVivaldiDebugCatagories && dbgcatagory))                 \
		    {                                                           \
        DbgPrint(DRIVERNAME);                                   \
        DbgPrint(fmt, __VA_ARGS__);                             \
		    }                                                           \
}
#else
#define CrosEcVivaldiPrint(dbglevel, fmt, ...) {                       \
}
#endif
#endif