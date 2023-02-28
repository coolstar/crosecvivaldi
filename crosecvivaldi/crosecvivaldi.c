#define DESCRIPTOR_DEF
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
	if (pDevice->functionRowCount) {
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
	else if (localArg.settingsRequest == CSVivaldiRequestUpdateButton) {
		CrosVivaldiMediaReport report = { 0 };
		report.ReportID = REPORTID_MEDIA;
		report.ControlCode = (localArg.args.button.button >> 1);
		size_t bytesWritten;
		CrosEcVivaldiProcessVendorReport(pDevice, &report, sizeof(report), &bytesWritten);
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

	if (!NT_SUCCESS(GetArrayProperty(FxDevice, "function-row-physmap", (UINT8*)pDevice->functionRowKeys, &pDevice->functionRowCount))) {
		DbgPrint("Warning: Vivaldi not found\n");
		pDevice->functionRowCount = 0;
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
	WDF_IO_QUEUE_CONFIG           queueConfig;
	WDF_OBJECT_ATTRIBUTES         attributes;
	WDFDEVICE                     device;
	WDFQUEUE                      queue;
	PCROSECVIVALDI_CONTEXT               devContext;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	CrosEcVivaldiPrint(DEBUG_LEVEL_INFO, DBG_PNP,
		"CrosEcVivaldiEvtDeviceAdd called\n");

	//
	// Tell framework this is a filter driver. Filter drivers by default are  
	// not power policy owners. This works well for this driver because
	// HIDclass driver is the power policy owner for HID minidrivers.
	//

	WdfFdoInitSetFilter(DeviceInit);

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

	//
	// Create manual I/O queue to take care of hid report read requests
	//

	devContext = GetDeviceContext(device);

	devContext->FxDevice = device;

	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);

	queueConfig.EvtIoInternalDeviceControl = CrosEcVivaldiEvtInternalDeviceControl;

	status = WdfIoQueueCreate(device,
		&queueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		&queue
	);

	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_PNP,
			"WdfIoQueueCreate failed 0x%x\n", status);

		return status;
	}

	WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);

	queueConfig.PowerManaged = WdfTrue;

	status = WdfIoQueueCreate(device,
		&queueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		&devContext->ReportQueue
	);

	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_PNP,
			"WdfIoQueueCreate failed 0x%x\n", status);

		return status;
	}

	return status;
}

VOID
CrosEcVivaldiEvtInternalDeviceControl(
	IN WDFQUEUE     Queue,
	IN WDFREQUEST   Request,
	IN size_t       OutputBufferLength,
	IN size_t       InputBufferLength,
	IN ULONG        IoControlCode
)
{
	NTSTATUS            status = STATUS_SUCCESS;
	WDFDEVICE           device;
	PCROSECVIVALDI_CONTEXT     devContext;
	BOOLEAN             completeRequest = TRUE;

	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);

	device = WdfIoQueueGetDevice(Queue);
	devContext = GetDeviceContext(device);

	CrosEcVivaldiPrint(DEBUG_LEVEL_INFO, DBG_IOCTL,
		"%s, Queue:0x%p, Request:0x%p\n",
		DbgHidInternalIoctlString(IoControlCode),
		Queue,
		Request
	);

	//
	// Please note that HIDCLASS provides the buffer in the Irp->UserBuffer
	// field irrespective of the ioctl buffer type. However, framework is very
	// strict about type checking. You cannot get Irp->UserBuffer by using
	// WdfRequestRetrieveOutputMemory if the ioctl is not a METHOD_NEITHER
	// internal ioctl. So depending on the ioctl code, we will either
	// use retreive function or escape to WDM to get the UserBuffer.
	//

	switch (IoControlCode)
	{

	case IOCTL_HID_GET_DEVICE_DESCRIPTOR:
		//
		// Retrieves the device's HID descriptor.
		//
		status = CrosEcVivaldiGetHidDescriptor(device, Request);
		break;

	case IOCTL_HID_GET_DEVICE_ATTRIBUTES:
		//
		//Retrieves a device's attributes in a HID_DEVICE_ATTRIBUTES structure.
		//
		status = CrosEcVivaldiGetDeviceAttributes(Request);
		break;

	case IOCTL_HID_GET_REPORT_DESCRIPTOR:
		//
		//Obtains the report descriptor for the HID device.
		//
		status = CrosEcVivaldiGetReportDescriptor(device, Request);
		break;

	case IOCTL_HID_GET_STRING:
		//
		// Requests that the HID minidriver retrieve a human-readable string
		// for either the manufacturer ID, the product ID, or the serial number
		// from the string descriptor of the device. The minidriver must send
		// a Get String Descriptor request to the device, in order to retrieve
		// the string descriptor, then it must extract the string at the
		// appropriate index from the string descriptor and return it in the
		// output buffer indicated by the IRP. Before sending the Get String
		// Descriptor request, the minidriver must retrieve the appropriate
		// index for the manufacturer ID, the product ID or the serial number
		// from the device extension of a top level collection associated with
		// the device.
		//
		status = CrosEcVivaldiGetString(Request);
		break;

	case IOCTL_HID_WRITE_REPORT:
	case IOCTL_HID_SET_OUTPUT_REPORT:
		//
		//Transmits a class driver-supplied report to the device.
		//
		status = CrosEcVivaldiWriteReport(devContext, Request);
		break;

	case IOCTL_HID_READ_REPORT:
	case IOCTL_HID_GET_INPUT_REPORT:
		//
		// Returns a report from the device into a class driver-supplied buffer.
		// 
		status = CrosEcVivaldiReadReport(devContext, Request, &completeRequest);
		break;

	case IOCTL_HID_ACTIVATE_DEVICE:
		//
		// Makes the device ready for I/O operations.
		//
	case IOCTL_HID_DEACTIVATE_DEVICE:
		//
		// Causes the device to cease operations and terminate all outstanding
		// I/O requests.
		//
	default:
		status = STATUS_NOT_SUPPORTED;
		break;
	}

	if (completeRequest)
	{
		WdfRequestComplete(Request, status);

		CrosEcVivaldiPrint(DEBUG_LEVEL_INFO, DBG_IOCTL,
			"%s completed, Queue:0x%p, Request:0x%p\n",
			DbgHidInternalIoctlString(IoControlCode),
			Queue,
			Request
		);
	}
	else
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_INFO, DBG_IOCTL,
			"%s deferred, Queue:0x%p, Request:0x%p\n",
			DbgHidInternalIoctlString(IoControlCode),
			Queue,
			Request
		);
	}

	return;
}

NTSTATUS
CrosEcVivaldiGetHidDescriptor(
	IN WDFDEVICE Device,
	IN WDFREQUEST Request
)
{
	NTSTATUS            status = STATUS_SUCCESS;
	size_t              bytesToCopy = 0;
	WDFMEMORY           memory;

	UNREFERENCED_PARAMETER(Device);

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiGetHidDescriptor Entry\n");

	//
	// This IOCTL is METHOD_NEITHER so WdfRequestRetrieveOutputMemory
	// will correctly retrieve buffer from Irp->UserBuffer. 
	// Remember that HIDCLASS provides the buffer in the Irp->UserBuffer
	// field irrespective of the ioctl buffer type. However, framework is very
	// strict about type checking. You cannot get Irp->UserBuffer by using
	// WdfRequestRetrieveOutputMemory if the ioctl is not a METHOD_NEITHER
	// internal ioctl.
	//
	status = WdfRequestRetrieveOutputMemory(Request, &memory);

	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"WdfRequestRetrieveOutputMemory failed 0x%x\n", status);

		return status;
	}

	//
	// Use hardcoded "HID Descriptor" 
	//
	bytesToCopy = DefaultHidDescriptor.bLength;

	if (bytesToCopy == 0)
	{
		status = STATUS_INVALID_DEVICE_STATE;

		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"DefaultHidDescriptor is zero, 0x%x\n", status);

		return status;
	}

	status = WdfMemoryCopyFromBuffer(memory,
		0, // Offset
		(PVOID)&DefaultHidDescriptor,
		bytesToCopy);

	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"WdfMemoryCopyFromBuffer failed 0x%x\n", status);

		return status;
	}

	//
	// Report how many bytes were copied
	//
	WdfRequestSetInformation(Request, bytesToCopy);

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiGetHidDescriptor Exit = 0x%x\n", status);

	return status;
}

NTSTATUS
CrosEcVivaldiGetReportDescriptor(
	IN WDFDEVICE Device,
	IN WDFREQUEST Request
)
{
	NTSTATUS            status = STATUS_SUCCESS;
	ULONG_PTR           bytesToCopy;
	WDFMEMORY           memory;

	UNREFERENCED_PARAMETER(Device);

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiGetReportDescriptor Entry\n");

	//
	// This IOCTL is METHOD_NEITHER so WdfRequestRetrieveOutputMemory
	// will correctly retrieve buffer from Irp->UserBuffer. 
	// Remember that HIDCLASS provides the buffer in the Irp->UserBuffer
	// field irrespective of the ioctl buffer type. However, framework is very
	// strict about type checking. You cannot get Irp->UserBuffer by using
	// WdfRequestRetrieveOutputMemory if the ioctl is not a METHOD_NEITHER
	// internal ioctl.
	//
	status = WdfRequestRetrieveOutputMemory(Request, &memory);
	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"WdfRequestRetrieveOutputMemory failed 0x%x\n", status);

		return status;
	}

	//
	// Use hardcoded Report descriptor
	//
	bytesToCopy = DefaultHidDescriptor.DescriptorList[0].wReportLength;

	if (bytesToCopy == 0)
	{
		status = STATUS_INVALID_DEVICE_STATE;

		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"DefaultHidDescriptor's reportLength is zero, 0x%x\n", status);

		return status;
	}

	status = WdfMemoryCopyFromBuffer(memory,
		0,
		(PVOID)DefaultReportDescriptor,
		bytesToCopy);
	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"WdfMemoryCopyFromBuffer failed 0x%x\n", status);

		return status;
	}

	//
	// Report how many bytes were copied
	//
	WdfRequestSetInformation(Request, bytesToCopy);

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiGetReportDescriptor Exit = 0x%x\n", status);

	return status;
}


NTSTATUS
CrosEcVivaldiGetDeviceAttributes(
	IN WDFREQUEST Request
)
{
	NTSTATUS                 status = STATUS_SUCCESS;
	PHID_DEVICE_ATTRIBUTES   deviceAttributes = NULL;

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiGetDeviceAttributes Entry\n");

	//
	// This IOCTL is METHOD_NEITHER so WdfRequestRetrieveOutputMemory
	// will correctly retrieve buffer from Irp->UserBuffer. 
	// Remember that HIDCLASS provides the buffer in the Irp->UserBuffer
	// field irrespective of the ioctl buffer type. However, framework is very
	// strict about type checking. You cannot get Irp->UserBuffer by using
	// WdfRequestRetrieveOutputMemory if the ioctl is not a METHOD_NEITHER
	// internal ioctl.
	//
	status = WdfRequestRetrieveOutputBuffer(Request,
		sizeof(HID_DEVICE_ATTRIBUTES),
		(PVOID*)&deviceAttributes,
		NULL);
	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"WdfRequestRetrieveOutputBuffer failed 0x%x\n", status);

		return status;
	}

	//
	// Set USB device descriptor
	//

	deviceAttributes->Size = sizeof(HID_DEVICE_ATTRIBUTES);
	deviceAttributes->VendorID = CROSECVIVALDI_VID;
	deviceAttributes->ProductID = CROSECVIVALDI_PID;
	deviceAttributes->VersionNumber = CROSECVIVALDI_VERSION;

	//
	// Report how many bytes were copied
	//
	WdfRequestSetInformation(Request, sizeof(HID_DEVICE_ATTRIBUTES));

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiGetDeviceAttributes Exit = 0x%x\n", status);

	return status;
}

NTSTATUS
CrosEcVivaldiGetString(
	IN WDFREQUEST Request
)
{

	NTSTATUS status = STATUS_SUCCESS;
	PWSTR pwstrID;
	size_t lenID;
	WDF_REQUEST_PARAMETERS params;
	void* pStringBuffer = NULL;

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiGetString Entry\n");

	WDF_REQUEST_PARAMETERS_INIT(&params);
	WdfRequestGetParameters(Request, &params);

	switch ((ULONG_PTR)params.Parameters.DeviceIoControl.Type3InputBuffer & 0xFFFF)
	{
	case HID_STRING_ID_IMANUFACTURER:
		pwstrID = L"CrosEcVivaldi.\0";
		break;

	case HID_STRING_ID_IPRODUCT:
		pwstrID = L"MaxTouch Touch Screen\0";
		break;

	case HID_STRING_ID_ISERIALNUMBER:
		pwstrID = L"123123123\0";
		break;

	default:
		pwstrID = NULL;
		break;
	}

	lenID = pwstrID ? wcslen(pwstrID) * sizeof(WCHAR) + sizeof(UNICODE_NULL) : 0;

	if (pwstrID == NULL)
	{

		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"CrosEcVivaldiGetString Invalid request type\n");

		status = STATUS_INVALID_PARAMETER;

		return status;
	}

	status = WdfRequestRetrieveOutputBuffer(Request,
		lenID,
		&pStringBuffer,
		&lenID);

	if (!NT_SUCCESS(status))
	{

		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"CrosEcVivaldiGetString WdfRequestRetrieveOutputBuffer failed Status 0x%x\n", status);

		return status;
	}

	RtlCopyMemory(pStringBuffer, pwstrID, lenID);

	WdfRequestSetInformation(Request, lenID);

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiGetString Exit = 0x%x\n", status);

	return status;
}

NTSTATUS
CrosEcVivaldiWriteReport(
	IN PCROSECVIVALDI_CONTEXT DevContext,
	IN WDFREQUEST Request
)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDF_REQUEST_PARAMETERS params;
	PHID_XFER_PACKET transferPacket = NULL;
	size_t bytesWritten = 0;

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiWriteReport Entry\n");

	WDF_REQUEST_PARAMETERS_INIT(&params);
	WdfRequestGetParameters(Request, &params);

	if (params.Parameters.DeviceIoControl.InputBufferLength < sizeof(HID_XFER_PACKET))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"CrosEcVivaldiWriteReport Xfer packet too small\n");

		status = STATUS_BUFFER_TOO_SMALL;
	}
	else
	{

		transferPacket = (PHID_XFER_PACKET)WdfRequestWdmGetIrp(Request)->UserBuffer;

		if (transferPacket == NULL)
		{
			CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
				"CrosEcVivaldiWriteReport No xfer packet\n");

			status = STATUS_INVALID_DEVICE_REQUEST;
		}
		else
		{
			//
			// switch on the report id
			//

			switch (transferPacket->reportId)
			{
			default:
				CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
					"CrosEcVivaldiWriteReport Unhandled report type %d\n", transferPacket->reportId);

				status = STATUS_INVALID_PARAMETER;

				break;
			}
		}
	}

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiWriteReport Exit = 0x%x\n", status);

	return status;

}

NTSTATUS
CrosEcVivaldiProcessVendorReport(
	IN PCROSECVIVALDI_CONTEXT DevContext,
	IN PVOID ReportBuffer,
	IN ULONG ReportBufferLen,
	OUT size_t* BytesWritten
)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDFREQUEST reqRead;
	PVOID pReadReport = NULL;
	size_t bytesReturned = 0;

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiProcessVendorReport Entry\n");

	status = WdfIoQueueRetrieveNextRequest(DevContext->ReportQueue,
		&reqRead);

	if (NT_SUCCESS(status))
	{
		status = WdfRequestRetrieveOutputBuffer(reqRead,
			ReportBufferLen,
			&pReadReport,
			&bytesReturned);

		if (NT_SUCCESS(status))
		{
			//
			// Copy ReportBuffer into read request
			//

			if (bytesReturned > ReportBufferLen)
			{
				bytesReturned = ReportBufferLen;
			}

			RtlCopyMemory(pReadReport,
				ReportBuffer,
				bytesReturned);

			//
			// Complete read with the number of bytes returned as info
			//

			WdfRequestCompleteWithInformation(reqRead,
				status,
				bytesReturned);

			CrosEcVivaldiPrint(DEBUG_LEVEL_INFO, DBG_IOCTL,
				"CrosEcVivaldiProcessVendorReport %d bytes returned\n", bytesReturned);

			//
			// Return the number of bytes written for the write request completion
			//

			*BytesWritten = bytesReturned;

			CrosEcVivaldiPrint(DEBUG_LEVEL_INFO, DBG_IOCTL,
				"%s completed, Queue:0x%p, Request:0x%p\n",
				DbgHidInternalIoctlString(IOCTL_HID_READ_REPORT),
				DevContext->ReportQueue,
				reqRead);
		}
		else
		{
			CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
				"WdfRequestRetrieveOutputBuffer failed Status 0x%x\n", status);
		}
	}
	else
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"WdfIoQueueRetrieveNextRequest failed Status 0x%x\n", status);
	}

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiProcessVendorReport Exit = 0x%x\n", status);

	return status;
}

NTSTATUS
CrosEcVivaldiReadReport(
	IN PCROSECVIVALDI_CONTEXT DevContext,
	IN WDFREQUEST Request,
	OUT BOOLEAN* CompleteRequest
)
{
	NTSTATUS status = STATUS_SUCCESS;

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiReadReport Entry\n");

	//
	// Forward this read request to our manual queue
	// (in other words, we are going to defer this request
	// until we have a corresponding write request to
	// match it with)
	//

	status = WdfRequestForwardToIoQueue(Request, DevContext->ReportQueue);

	if (!NT_SUCCESS(status))
	{
		CrosEcVivaldiPrint(DEBUG_LEVEL_ERROR, DBG_IOCTL,
			"WdfRequestForwardToIoQueue failed Status 0x%x\n", status);
	}
	else
	{
		*CompleteRequest = FALSE;
	}

	CrosEcVivaldiPrint(DEBUG_LEVEL_VERBOSE, DBG_IOCTL,
		"CrosEcVivaldiReadReport Exit = 0x%x\n", status);

	return status;
}

PCHAR
DbgHidInternalIoctlString(
	IN ULONG IoControlCode
)
{
	switch (IoControlCode)
	{
	case IOCTL_HID_GET_DEVICE_DESCRIPTOR:
		return "IOCTL_HID_GET_DEVICE_DESCRIPTOR";
	case IOCTL_HID_GET_REPORT_DESCRIPTOR:
		return "IOCTL_HID_GET_REPORT_DESCRIPTOR";
	case IOCTL_HID_READ_REPORT:
		return "IOCTL_HID_READ_REPORT";
	case IOCTL_HID_GET_DEVICE_ATTRIBUTES:
		return "IOCTL_HID_GET_DEVICE_ATTRIBUTES";
	case IOCTL_HID_WRITE_REPORT:
		return "IOCTL_HID_WRITE_REPORT";
	case IOCTL_HID_SET_FEATURE:
		return "IOCTL_HID_SET_FEATURE";
	case IOCTL_HID_GET_FEATURE:
		return "IOCTL_HID_GET_FEATURE";
	case IOCTL_HID_GET_STRING:
		return "IOCTL_HID_GET_STRING";
	case IOCTL_HID_ACTIVATE_DEVICE:
		return "IOCTL_HID_ACTIVATE_DEVICE";
	case IOCTL_HID_DEACTIVATE_DEVICE:
		return "IOCTL_HID_DEACTIVATE_DEVICE";
	case IOCTL_HID_SEND_IDLE_NOTIFICATION_REQUEST:
		return "IOCTL_HID_SEND_IDLE_NOTIFICATION_REQUEST";
	case IOCTL_HID_SET_OUTPUT_REPORT:
		return "IOCTL_HID_SET_OUTPUT_REPORT";
	case IOCTL_HID_GET_INPUT_REPORT:
		return "IOCTL_HID_GET_INPUT_REPORT";
	default:
		return "Unknown IOCTL";
	}
}