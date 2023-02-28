#if !defined(_CROSKEYBOARD_COMMON_H_)
#define _CROSECVIVALDI_COMMON_H_

//
//These are the device attributes returned by vmulti in response
// to IOCTL_HID_GET_DEVICE_ATTRIBUTES.
//

#define CROSECVIVALDI_PID              0x0007
#define CROSECVIVALDI_VID              0x18D1
#define CROSECVIVALDI_VERSION          0x0001

//
// These are the report ids
//

#define REPORTID_MEDIA          0x01

#pragma pack(1)
typedef struct _CROSVIVALDI_MEDIA_REPORT
{

	BYTE      ReportID;

	BYTE	  ControlCode;

} CrosVivaldiMediaReport;

#endif
#pragma once