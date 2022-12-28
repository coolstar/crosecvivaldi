#include "driver.h"
#include "stdint.h"

static ULONG CrosEcVivaldiDebugLevel = 100;
static ULONG CrosEcVivaldiDebugCatagories = DBG_INIT || DBG_PNP || DBG_IOCTL;

NTSTATUS
DriverEntry(
	__in PDRIVER_OBJECT  DriverObject,
	__in PUNICODE_STRING RegistryPath
)
{
	NTSTATUS               status = STATUS_SUCCESS;
	WDF_DRIVER_CONFIG      config;
	WDF_OBJECT_ATTRIBUTES  attributes;

	CrosEcVivaldiPrint(DEBUG_LEVEL_INFO, DBG_INIT,
		"Driver Entry\n");

	WDF_DRIVER_CONFIG_INIT(&config, CrosEcVivaldiEvtDeviceAdd);

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

	//
	// Create a framework driver object to represent our driver.
	//

	status = WdfDriverCreate(DriverObject,
		RegistryPath,
		&attributes,
		&config,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_INIT,
			"WdfDriverCreate failed with status 0x%x\n", status);
	}

	return status;
}

NTSTATUS ConnectToEc(
	_In_ WDFDEVICE FxDevice
) {
	PCROSECVIVALDI_CONTEXT pDevice = GetDeviceContext(FxDevice);
	WDF_OBJECT_ATTRIBUTES objectAttributes;

	WDF_OBJECT_ATTRIBUTES_INIT(&objectAttributes);
	objectAttributes.ParentObject = FxDevice;

	WDFIOTARGET busIoTarget = NULL;

	NTSTATUS status = WdfIoTargetCreate(FxDevice,
		&objectAttributes,
		&busIoTarget
	);
	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(
			DEBUG_LEVEL_ERROR,
			DBG_IOCTL,
			"Error creating IoTarget object - 0x%x\n",
			status);
		if (busIoTarget)
			WdfObjectDelete(busIoTarget);
		return status;
	}

	DECLARE_CONST_UNICODE_STRING(busDosDeviceName, L"\\DosDevices\\GOOG0004");

	WDF_IO_TARGET_OPEN_PARAMS openParams;
	WDF_IO_TARGET_OPEN_PARAMS_INIT_OPEN_BY_NAME(
		&openParams,
		&busDosDeviceName,
		(GENERIC_READ | GENERIC_WRITE));

	openParams.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
	openParams.CreateDisposition = FILE_OPEN;
	openParams.FileAttributes = FILE_ATTRIBUTE_NORMAL;

	CROSEC_INTERFACE_STANDARD CrosEcInterface;
	RtlZeroMemory(&CrosEcInterface, sizeof(CrosEcInterface));

	status = WdfIoTargetOpen(busIoTarget, &openParams);
	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(
			DEBUG_LEVEL_ERROR,
			DBG_IOCTL,
			"Error opening IoTarget object - 0x%x\n",
			status);
		WdfObjectDelete(busIoTarget);
		return status;
	}

	status = WdfIoTargetQueryForInterface(busIoTarget,
		&GUID_CROSEC_INTERFACE_STANDARD,
		(PINTERFACE)&CrosEcInterface,
		sizeof(CrosEcInterface),
		1,
		NULL);
	WdfIoTargetClose(busIoTarget);
	if (!NT_SUCCESS(status)) {
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_PNP,
			"WdfFdoQueryForInterface failed 0x%x\n", status);
		return status;
	}

	pDevice->CrosEcBusContext = CrosEcInterface.InterfaceHeader.Context;
	pDevice->CrosEcCmdXferStatus = CrosEcInterface.CmdXferStatus;
	return status;
}

NTSTATUS
OnPrepareHardware(
	_In_  WDFDEVICE     FxDevice,
	_In_  WDFCMRESLIST  FxResourcesRaw,
	_In_  WDFCMRESLIST  FxResourcesTranslated
)
/*++

Routine Description:

This routine caches the SPB resource connection ID.

Arguments:

FxDevice - a handle to the framework device object
FxResourcesRaw - list of translated hardware resources that
the PnP manager has assigned to the device
FxResourcesTranslated - list of raw hardware resources that
the PnP manager has assigned to the device

Return Value:

Status

--*/
{
	PCROSECVIVALDI_CONTEXT pDevice = GetDeviceContext(FxDevice);
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(FxResourcesRaw);
	UNREFERENCED_PARAMETER(FxResourcesTranslated);

	status = ConnectToEc(FxDevice);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	(*pDevice->CrosEcCmdXferStatus)(pDevice->CrosEcBusContext, NULL);

	return status;
}

int CSVivaldiArg2;

const UINT8 scancode_translate_table[128] = {
  0xff, 0x43, 0x41, 0x3f, 0x3d, 0x3b, 0x3c, 0x58, 0x64, 0x44,
  0x42, 0x40, 0x3e, 0x0f, 0x29, 0x59, 0x65, 0x38, 0x2a, 0x70,
  0x1d, 0x10, 0x02, 0x5a, 0x66, 0x71, 0x2c, 0x1f, 0x1e, 0x11,
  0x03, 0x5b, 0x67, 0x2e, 0x2d, 0x20, 0x12, 0x05, 0x04, 0x5c,
  0x68, 0x39, 0x2f, 0x21, 0x14, 0x13, 0x06, 0x5d, 0x69, 0x31,
  0x30, 0x23, 0x22, 0x15, 0x07, 0x5e, 0x6a, 0x72, 0x32, 0x24,
  0x16, 0x08, 0x09, 0x5f, 0x6b, 0x33, 0x25, 0x17, 0x18, 0x0b,
  0x0a, 0x60, 0x6c, 0x34, 0x35, 0x26, 0x27, 0x19, 0x0c, 0x61,
  0x6d, 0x73, 0x28, 0x74, 0x1a, 0x0d, 0x62, 0x6e, 0x3a, 0x36,
  0x1c, 0x1b, 0x75, 0x2b, 0x63, 0x76, 0x55, 0x56, 0x77, 0x78,
  0x79, 0x7a, 0x0e, 0x7b, 0x7c, 0x4f, 0x7d, 0x4b, 0x47, 0x7e,
  0x7f, 0x6f, 0x52, 0x53, 0x50, 0x4c, 0x4d, 0x48, 0x01, 0x45,
  0x57, 0x4e, 0x51, 0x4a, 0x37, 0x49, 0x46, 0x54,
};

UINT8 scancode_translate_set2_to_1(UINT8 code, USHORT* flags)
{
	if (code & 0x80) {
		*flags |= KEY_E0;
		if (code == 0x83)
			return 0x41;
		return code & ~0x80;
	}
	return scancode_translate_table[code];
}

VOID CSVivaldiLoadSettings(PCROSECVIVALDI_CONTEXT  pDevice) {
	CSVivaldiSettingsArg newArg;
	RtlZeroMemory(&newArg, sizeof(CSVivaldiSettingsArg));
	newArg.argSz = sizeof(CSVivaldiSettingsArg);
	newArg.settingsRequest = CSVivaldiRequestLoadSettings;
	newArg.args.settings.functionRowCount = pDevice->functionRowCount;
	for (int i = 0; i < pDevice->functionRowCount; i++) {
		newArg.args.settings.functionRowKeys[i].MakeCode = scancode_translate_set2_to_1(
			pDevice->functionRowKeys[i],
			&newArg.args.settings.functionRowKeys[i].Flags
		);
	}
	ExNotifyCallback(pDevice->CSSettingsCallback, &newArg, &CSVivaldiArg2);
}

VOID CsVivaldiCallbackFunction(
	PCROSECVIVALDI_CONTEXT pDevice,
	CSVivaldiSettingsArg* arg,
	PVOID Argument2
) {
	if (!pDevice) {
		return;
	}
	if (Argument2 == &CSVivaldiArg2) {
		return;
	}

	CSVivaldiSettingsArg localArg;
	RtlZeroMemory(&localArg, sizeof(CSVivaldiSettingsArg));
	RtlCopyMemory(&localArg, arg, min(arg->argSz, sizeof(CSVivaldiSettingsArg)));

	if (localArg.settingsRequest == CSVivaldiRequestEndpointRegister) {
		CSVivaldiLoadSettings(pDevice);
	}
}

NTSTATUS
OnSelfManagedIoInit(
	_In_
	WDFDEVICE FxDevice
) {
	PCROSECVIVALDI_CONTEXT pDevice;
	pDevice = GetDeviceContext(FxDevice);

	NTSTATUS status = STATUS_SUCCESS;

	// CS Keyboard Callback

	UNICODE_STRING CSKeyboardSettingsCallbackAPI;
	RtlInitUnicodeString(&CSKeyboardSettingsCallbackAPI, L"\\CallBack\\CsKeyboardSettingsCallbackAPI");


	OBJECT_ATTRIBUTES attributes;
	InitializeObjectAttributes(&attributes,
		&CSKeyboardSettingsCallbackAPI,
		OBJ_KERNEL_HANDLE | OBJ_OPENIF | OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
		NULL,
		NULL
	);
	status = ExCreateCallback(&pDevice->CSSettingsCallback, &attributes, TRUE, TRUE);
	if (!NT_SUCCESS(status)) {

		return status;
	}

	pDevice->CSSettingsCallbackObj = ExRegisterCallback(pDevice->CSSettingsCallback,
		CsVivaldiCallbackFunction,
		pDevice
	);
	if (!pDevice->CSSettingsCallbackObj) {
		return STATUS_NO_CALLBACK_ACTIVE;
	}

	CSVivaldiSettingsArg newArg;
	RtlZeroMemory(&newArg, sizeof(CSVivaldiSettingsArg));
	newArg.argSz = sizeof(CSVivaldiSettingsArg);
	newArg.settingsRequest = CSVivaldiRequestEndpointRegister;
	ExNotifyCallback(pDevice->CSSettingsCallback, &newArg, &CSVivaldiArg2);

	return status;
}

NTSTATUS
OnReleaseHardware(
	_In_  WDFDEVICE     FxDevice,
	_In_  WDFCMRESLIST  FxResourcesTranslated
)
/*++

Routine Description:

Arguments:

FxDevice - a handle to the framework device object
FxResourcesTranslated - list of raw hardware resources that
the PnP manager has assigned to the device

Return Value:

Status

--*/
{
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(FxResourcesTranslated);

	PCROSECVIVALDI_CONTEXT pDevice;
	pDevice = GetDeviceContext(FxDevice);

	if (pDevice->CSSettingsCallbackObj) {
		ExUnregisterCallback(pDevice->CSSettingsCallbackObj);
		pDevice->CSSettingsCallbackObj = NULL;
	}

	if (pDevice->CSSettingsCallback) {
		ObfDereferenceObject(pDevice->CSSettingsCallback);
		pDevice->CSSettingsCallback = NULL;
	}

	return status;
}

static NTSTATUS send_ec_command(
	_In_ PCROSECVIVALDI_CONTEXT pDevice,
	UINT32 cmd,
	UINT8* out,
	size_t outSize,
	UINT8* in,
	size_t inSize)
{
	PCROSEC_COMMAND msg = ExAllocatePoolWithTag(NonPagedPool, sizeof(CROSEC_COMMAND*) + max(outSize, inSize), CROSECVIVALDI_POOL_TAG);
	if (!msg) {
		return STATUS_NO_MEMORY;
	}
	msg->Version = 0;
	msg->Command = cmd;
	msg->OutSize = (UINT32)outSize;
	msg->InSize = (UINT32)inSize;

	if (outSize)
		memcpy(msg->Data, out, outSize);

	NTSTATUS status = (*pDevice->CrosEcCmdXferStatus)(pDevice->CrosEcBusContext, msg);
	if (!NT_SUCCESS(status)) {
		goto exit;
	}

	if (in && inSize) {
		memcpy(in, msg->Data, inSize);
	}

exit:
	ExFreePoolWithTag(msg, CROSECVIVALDI_POOL_TAG);
	return status;
}

static NTSTATUS GetArrayProperty(
	_In_ WDFDEVICE FxDevice,
	const char* propertyStr,
	UINT8* property,
	UINT8* propertyLen
) {
	WDFMEMORY outputMemory = WDF_NO_HANDLE;

	NTSTATUS status = STATUS_ACPI_NOT_INITIALIZED;

	size_t inputBufferLen = sizeof(ACPI_GET_DEVICE_SPECIFIC_DATA) + strlen(propertyStr) + 1;
	ACPI_GET_DEVICE_SPECIFIC_DATA* inputBuffer = ExAllocatePoolWithTag(NonPagedPool, inputBufferLen, CROSECVIVALDI_POOL_TAG);
	if (!inputBuffer) {
		goto Exit;
	}
	RtlZeroMemory(inputBuffer, inputBufferLen);

	inputBuffer->Signature = IOCTL_ACPI_GET_DEVICE_SPECIFIC_DATA_SIGNATURE;

	unsigned char uuidend[] = { 0x8a, 0x91, 0xbc, 0x9b, 0xbf, 0x4a, 0xa3, 0x01 };

	inputBuffer->Section.Data1 = 0xdaffd814;
	inputBuffer->Section.Data2 = 0x6eba;
	inputBuffer->Section.Data3 = 0x4d8c;
	memcpy(inputBuffer->Section.Data4, uuidend, sizeof(uuidend)); //Avoid Windows defender false positive

	strcpy((char*)inputBuffer->PropertyName, propertyStr);
	inputBuffer->PropertyNameLength = (ULONG)strlen(propertyStr) + 1;

	ACPI_EVAL_OUTPUT_BUFFER outputSizeBuffer = { 0 };
	WDF_MEMORY_DESCRIPTOR outputSizeMemDesc;
	WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&outputSizeMemDesc, &outputSizeBuffer, (ULONG)sizeof(outputSizeBuffer));

	WDF_MEMORY_DESCRIPTOR inputMemDesc;
	WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&inputMemDesc, inputBuffer, (ULONG)inputBufferLen);

	// Send the request along
	status = WdfIoTargetSendInternalIoctlSynchronously(
		WdfDeviceGetIoTarget(FxDevice),
		NULL,
		IOCTL_ACPI_GET_DEVICE_SPECIFIC_DATA,
		&inputMemDesc,
		&outputSizeMemDesc,
		NULL,
		NULL
	);

	if (status != STATUS_BUFFER_OVERFLOW) {
		CrosEcVivaldiPrint(
			DEBUG_LEVEL_ERROR,
			DBG_PNP,
			"Error getting device data - 0x%x\n",
			status);
		goto Exit;
	}

	PACPI_EVAL_OUTPUT_BUFFER outputBuffer;
	size_t outputArgumentBufferSize = outputSizeBuffer.Length;
	size_t outputBufferSize = FIELD_OFFSET(ACPI_EVAL_OUTPUT_BUFFER, Argument) + sizeof(ACPI_METHOD_ARGUMENT_V1) + outputArgumentBufferSize;

	WDF_OBJECT_ATTRIBUTES attributes;
	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	attributes.ParentObject = FxDevice;
	status = WdfMemoryCreate(&attributes,
		NonPagedPoolNx,
		0,
		outputBufferSize,
		&outputMemory,
		&outputBuffer);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	WDF_MEMORY_DESCRIPTOR outputMemDesc;
	WDF_MEMORY_DESCRIPTOR_INIT_HANDLE(&outputMemDesc, outputMemory, NULL);

	status = WdfIoTargetSendInternalIoctlSynchronously(
		WdfDeviceGetIoTarget(FxDevice),
		NULL,
		IOCTL_ACPI_GET_DEVICE_SPECIFIC_DATA,
		&inputMemDesc,
		&outputMemDesc,
		NULL,
		NULL
	);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	if (outputBuffer->Signature != ACPI_EVAL_OUTPUT_BUFFER_SIGNATURE_V1 &&
		outputBuffer->Count < 1 &&
		outputBuffer->Argument->Type != ACPI_METHOD_ARGUMENT_BUFFER &&
		outputBuffer->Argument->DataLength != sizeof(ACPI_METHOD_ARGUMENT)) {
		status = STATUS_ACPI_INVALID_ARGUMENT;
		goto Exit;
	}
	if (propertyLen) {
		*propertyLen = (UINT8)outputBuffer->Count;
	}

	PACPI_METHOD_ARGUMENT currArgument = &outputBuffer->Argument[0];
	for (ULONG i = 0; i < outputBuffer->Count; i++) {
		if (property) {
			property[i] = currArgument->Data[0] & 0xFF;
		}

		currArgument = ACPI_METHOD_NEXT_ARGUMENT(currArgument);
	}

Exit:
	if (inputBuffer) {
		ExFreePoolWithTag(inputBuffer, CROSECVIVALDI_POOL_TAG);
	}
	if (outputMemory != WDF_NO_HANDLE) {
		WdfObjectDelete(outputMemory);
	}
	return status;
}

enum ps2_action_key {
	PS2_KEY_ABSENT = 0,
	PS2_KEY_BACK,
	PS2_KEY_FORWARD,
	PS2_KEY_REFRESH,
	PS2_KEY_FULLSCREEN,
	PS2_KEY_OVERVIEW,
	PS2_KEY_BRIGHTNESS_DOWN,
	PS2_KEY_BRIGHTNESS_UP,
	PS2_KEY_VOL_MUTE,
	PS2_KEY_VOL_DOWN,
	PS2_KEY_VOL_UP,
	PS2_KEY_SNAPSHOT,
	PS2_KEY_PRIVACY_SCRN_TOGGLE,
	PS2_KEY_KBD_BKLIGHT_DOWN,
	PS2_KEY_KBD_BKLIGHT_UP,
	PS2_KEY_PLAY_PAUSE,
	PS2_KEY_NEXT_TRACK,
	PS2_KEY_PREV_TRACK,
	PS2_KEY_KBD_BKLIGHT_TOGGLE,
	PS2_KEY_MICMUTE,
	PS2_KEY_MENU,
};

static const enum ps2_action_key ps2_enum_val[] = {
	[TK_ABSENT] = PS2_KEY_ABSENT,
	[TK_BACK] = PS2_KEY_BACK,
	[TK_FORWARD] = PS2_KEY_FORWARD,
	[TK_REFRESH] = PS2_KEY_REFRESH,
	[TK_FULLSCREEN] = PS2_KEY_FULLSCREEN,
	[TK_OVERVIEW] = PS2_KEY_OVERVIEW,
	[TK_BRIGHTNESS_DOWN] = PS2_KEY_BRIGHTNESS_DOWN,
	[TK_BRIGHTNESS_UP] = PS2_KEY_BRIGHTNESS_UP,
	[TK_VOL_MUTE] = PS2_KEY_VOL_MUTE,
	[TK_VOL_DOWN] = PS2_KEY_VOL_DOWN,
	[TK_VOL_UP] = PS2_KEY_VOL_UP,
	[TK_SNAPSHOT] = PS2_KEY_SNAPSHOT,
	[TK_PRIVACY_SCRN_TOGGLE] = PS2_KEY_PRIVACY_SCRN_TOGGLE,
	[TK_KBD_BKLIGHT_DOWN] = PS2_KEY_KBD_BKLIGHT_DOWN,
	[TK_KBD_BKLIGHT_UP] = PS2_KEY_KBD_BKLIGHT_UP,
	[TK_PLAY_PAUSE] = PS2_KEY_PLAY_PAUSE,
	[TK_NEXT_TRACK] = PS2_KEY_NEXT_TRACK,
	[TK_PREV_TRACK] = PS2_KEY_PREV_TRACK,
	[TK_KBD_BKLIGHT_TOGGLE] = PS2_KEY_KBD_BKLIGHT_TOGGLE,
	[TK_MICMUTE] = PS2_KEY_MICMUTE,
	[TK_MENU] = PS2_KEY_MENU,
};

NTSTATUS
OnD0Entry(
	_In_  WDFDEVICE               FxDevice,
	_In_  WDF_POWER_DEVICE_STATE  FxPreviousState
)
/*++

Routine Description:

This routine allocates objects needed by the driver.

Arguments:

FxDevice - a handle to the framework device object
FxPreviousState - previous power state

Return Value:

Status

--*/
{
	PCROSECVIVALDI_CONTEXT pDevice = GetDeviceContext(FxDevice);
	UNREFERENCED_PARAMETER(FxPreviousState);
	NTSTATUS status = STATUS_SUCCESS;

	status = GetArrayProperty(FxDevice, "function-row-physmap", (UINT8*)pDevice->functionRowKeys, &pDevice->functionRowCount);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to get DSD: 0x%x. Trying to query EC directly\n", status);

		struct ec_response_keybd_config keybdConfig;

		status = send_ec_command(pDevice, EC_CMD_GET_KEYBD_CONFIG, NULL, 0, (UINT8*)&keybdConfig, sizeof(keybdConfig));
		if (!NT_SUCCESS(status)) {
			CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_PNP, "Failed get keyboard config\n");
			return status;
		}

		if (keybdConfig.num_top_row_keys == 0 || keybdConfig.num_top_row_keys > MAX_TOP_ROW_KEYS) {
			CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_PNP, "Bad response from EC. Vivaldi disabled!\n");
			return STATUS_INVALID_DEVICE_STATE;
		}

		pDevice->functionRowCount = keybdConfig.num_top_row_keys;
		for (int i = 0; i < pDevice->functionRowCount; i++) {
			pDevice->functionRowKeys[i] = ps2_enum_val[keybdConfig.action_keys[i]];
		}
	}

	return status;
}

NTSTATUS
OnD0Exit(
	_In_  WDFDEVICE               FxDevice,
	_In_  WDF_POWER_DEVICE_STATE  FxTargetState
)
/*++

Routine Description:

This routine destroys objects needed by the driver.

Arguments:

FxDevice - a handle to the framework device object
FxTargetState - target power state

Return Value:

Status

--*/
{
	UNREFERENCED_PARAMETER(FxDevice);
	UNREFERENCED_PARAMETER(FxTargetState);

	NTSTATUS status = STATUS_SUCCESS;

	return status;
}

NTSTATUS
CrosEcVivaldiEvtDeviceAdd(
	IN WDFDRIVER       Driver,
	IN PWDFDEVICE_INIT DeviceInit
)
{
	NTSTATUS                      status = STATUS_SUCCESS;
	WDF_OBJECT_ATTRIBUTES         attributes;
	WDFDEVICE                     device;
	PCROSECVIVALDI_CONTEXT               devContext;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	CrosEcVivaldiPrint(DEBUG_LEVEL_INFO, DBG_PNP,
		"CrosEcVivaldiEvtDeviceAdd called\n");

	{
		WDF_PNPPOWER_EVENT_CALLBACKS pnpCallbacks;
		WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpCallbacks);

		pnpCallbacks.EvtDevicePrepareHardware = OnPrepareHardware;
		pnpCallbacks.EvtDeviceReleaseHardware = OnReleaseHardware;
		pnpCallbacks.EvtDeviceSelfManagedIoInit = OnSelfManagedIoInit;
		pnpCallbacks.EvtDeviceD0Entry = OnD0Entry;
		pnpCallbacks.EvtDeviceD0Exit = OnD0Exit;

		WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpCallbacks);
	}

	//
	// Setup the device context
	//

	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, CROSECVIVALDI_CONTEXT);

	//
	// Create a framework device object.This call will in turn create
	// a WDM device object, attach to the lower stack, and set the
	// appropriate flags and attributes.
	//

	status = WdfDeviceCreate(&DeviceInit, &attributes, &device);

	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_PNP,
			"WdfDeviceCreate failed with status code 0x%x\n", status);

		return status;
	}

	{
		WDF_DEVICE_STATE deviceState;
		WDF_DEVICE_STATE_INIT(&deviceState);

		deviceState.NotDisableable = WdfFalse;
		WdfDeviceSetDeviceState(device, &deviceState);
	}

	devContext = GetDeviceContext(device);

	devContext->FxDevice = device;

	return status;
}