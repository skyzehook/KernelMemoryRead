#include <ntifs.h>
#include <wdm.h>

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS FromProcess,
	PVOID FromAddress,
	PEPROCESS ToProcess,
	PVOID ToAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T NumberOfBytesCopied
);

#define IOCTL_SET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)


DRIVER_UNLOAD DriverUnload;
NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

PEPROCESS g_TargetProcess = NULL;
PDEVICE_OBJECT g_DeviceObject = NULL;

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrint("KernelMemoryRead driver loaded!\n");


	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\KernelMemoryRead");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\KernelMemoryRead");

	NTSTATUS status = IoCreateDevice(
		DriverObject,
		0,
		&devName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&g_DeviceObject
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("IoCreateDevice failed: 0x%X\n", status);
		return status;
	}


	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("IoCreateSymbolicLink failed: 0x%X\n", status);
		IoDeleteDevice(g_DeviceObject);
		return status;
	}

	DbgPrint("Device and symbolic link created successfully\n");

	return STATUS_SUCCESS;
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SET_PID)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG))
		{
			ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS process = NULL;

			status = PsLookupProcessByProcessId((HANDLE)pid, &process);
			if (NT_SUCCESS(status))
			{
				if (g_TargetProcess)
					ObDereferenceObject(g_TargetProcess);

				g_TargetProcess = process;
				DbgPrint("target process set pID=%lu, EPROCESS=%p\n", pid, g_TargetProcess);

				SIZE_T bytesRead =  0;
				int value = 0;
				status = MmCopyVirtualMemory(
					g_TargetProcess,
					(PVOID)0x00911710, //target address
					PsGetCurrentProcess(),
					&value,
					sizeof(value),
					KernelMode,
					&bytesRead
				);

				if (NT_SUCCESS(status))
					DbgPrint("read memory: %d\n", value);
				else
					DbgPrint("memory read failed: 0x%X\n", status);


			}
			else
			{
				DbgPrint("PsLookupProcessByProcessId failed for pID=%lu\n", pid);
			}
		}
		else
		{
			status = STATUS_BUFFER_TOO_SMALL;
		}
	}
	else
	{
		status = STATUS_INVALID_DEVICE_REQUEST;
	}


	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	if (g_TargetProcess)
		ObDereferenceObject(g_TargetProcess);

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\KernelMemoryRead");
	IoDeleteSymbolicLink(&symLink);

	if (g_DeviceObject)
		IoDeleteDevice(g_DeviceObject);

	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("KernelMemoryRead driver unloaded!\n");
}
