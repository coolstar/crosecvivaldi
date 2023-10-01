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

#pragma warning(disable:4201)  // suppress nameless struct/union warning
#pragma warning(disable:4214)  // suppress bit field types other than int warning
#include <hidport.h>

#include "hidcommon.h"

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

//
// This is the default report descriptor for the Hid device provided
// by the mini driver in response to IOCTL_HID_GET_REPORT_DESCRIPTOR.
// 

typedef UCHAR HID_REPORT_DESCRIPTOR, * PHID_REPORT_DESCRIPTOR;

#ifdef DESCRIPTOR_DEF
HID_REPORT_DESCRIPTOR DefaultReportDescriptor[] = {
	//
	// Buttons report starts here
	//

	0x05, 0x0C, /*		Usage Page (Consumer Devices)		*/
	0x09, 0x01, /*		Usage (Consumer Control)			*/
	0xA1, 0x01, /*		Collection (Application)			*/
	0x85, REPORTID_MEDIA,	/*		Report ID=1				*/
	0x05, 0x0C, /*		Usage Page (Consumer Devices)		*/
	0x15, 0x00, /*		Logical Minimum (0)					*/
	0x25, 0x01, /*		Logical Maximum (1)					*/
	0x75, 0x01, /*		Report Size (1)						*/
	0x95, 0x02, /*		Report Count (2)					*/
	0x09, 0xE9, /*		Usage (Volume Up)					*/
	0x09, 0xEA, /*		Usage (Volume Down)					*/
	0x81, 0x02, /*		Input (Data, Variable, Absolute)	*/
	0x95, 0x06, /*		Report Count (6)					*/
	0x81, 0x01, /*		Input (Constant)					*/
	0xC0,        /*        End Collection                        */
};


//
// This is the default HID descriptor returned by the mini driver
// in response to IOCTL_HID_GET_DEVICE_DESCRIPTOR. The size
// of report descriptor is currently the size of DefaultReportDescriptor.
//

CONST HID_DESCRIPTOR DefaultHidDescriptor = {
	0x09,   // length of HID descriptor
	0x21,   // descriptor type == HID  0x21
	0x0100, // hid spec release
	0x00,   // country code == Not Specified
	0x01,   // number of HID class descriptors
	{ 0x22,   // descriptor type 
	sizeof(DefaultReportDescriptor) }  // total length of report descriptor
};
#endif

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
    CSVivaldiRequestLoadSettings,
    CSVivaldiRequestUpdateButton = 0x101
} CSVivaldiRequest;

#include <pshpack1.h>
typedef struct CSVivaldiSettingsArg {
    UINT32 argSz;
    CSVivaldiRequest settingsRequest;
    union args {
        struct {
            UINT8 functionRowCount;
            KeySetting functionRowKeys[16];
        } settings;
        struct {
            UINT8 button;
        } button;
    } args;
} CSVivaldiSettingsArg, * PCSVivaldiSettingsArg;
#include <poppack.h>

typedef struct _CROSECVIVALDI_CONTEXT
{
    WDFQUEUE ReportQueue;

    WDFQUEUE IdleQueue;

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
// Power Idle Workitem context
// 
typedef struct _IDLE_WORKITEM_CONTEXT
{
    // Handle to a WDF device object
    WDFDEVICE FxDevice;

    // Handle to a WDF request object
    WDFREQUEST FxRequest;

} IDLE_WORKITEM_CONTEXT, * PIDLE_WORKITEM_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(IDLE_WORKITEM_CONTEXT, GetIdleWorkItemContext)


//
// Function definitions
//

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_UNLOAD CrosEcVivaldiDriverUnload;

EVT_WDF_DRIVER_DEVICE_ADD CrosEcVivaldiEvtDeviceAdd;

EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL CrosEcVivaldiEvtInternalDeviceControl;

NTSTATUS
CrosEcVivaldiGetHidDescriptor(
	IN WDFDEVICE Device,
	IN WDFREQUEST Request
);

NTSTATUS
CrosEcVivaldiGetReportDescriptor(
	IN WDFDEVICE Device,
	IN WDFREQUEST Request
);

NTSTATUS
CrosEcVivaldiGetDeviceAttributes(
	IN WDFREQUEST Request
);

NTSTATUS
CrosEcVivaldiGetString(
	IN WDFREQUEST Request
);

NTSTATUS
CrosEcVivaldiWriteReport(
	IN PCROSECVIVALDI_CONTEXT DevContext,
	IN WDFREQUEST Request
);

NTSTATUS
CrosEcVivaldiProcessVendorReport(
	IN PCROSECVIVALDI_CONTEXT DevContext,
	IN PVOID ReportBuffer,
	IN ULONG ReportBufferLen,
	OUT size_t* BytesWritten
);

NTSTATUS
CrosEcVivaldiReadReport(
	IN PCROSECVIVALDI_CONTEXT DevContext,
	IN WDFREQUEST Request,
	OUT BOOLEAN* CompleteRequest
);

PCHAR
DbgHidInternalIoctlString(
	IN ULONG        IoControlCode
);

VOID
CrosEcVivaldiCompleteIdleIrp(
    IN PCROSECVIVALDI_CONTEXT FxDeviceContext
);

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