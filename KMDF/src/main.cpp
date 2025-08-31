#include <ntifs.h>
//Undeclared in ntifs.h functions
extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, 
		PEPROCESS TargetProcess, PVOID TargetAdress, 
		SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
}


void debug_print(PCSTR text)
{
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}
namespace driver {
	//control codes for driver
	namespace codes {
		//to setup a driver
		constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		//Read process memory
		constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		//Write Process memory
		constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}
	//for communication with UM
	struct Request {
		HANDLE process_id;
		PVOID target;
		PVOID buffer;
		SIZE_T size;
		SIZE_T return_size;
	};

	// IRP holds the data
	NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}

	NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}
	//to do
	NTSTATUS device_ctl(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);
		debug_print("[+] Device control called.\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		//Needed to determine which control code is passed to driver
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

		//When struct request comes from UM
		Request *request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);
		if (stack_irp == nullptr || request == nullptr)
		{
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}
		//Target process
		static PEPROCESS target_process = nullptr;

		const ULONG ctl_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;

		switch (ctl_code) {
		case codes::attach:
			status = PsLookupProcessByProcessId(request->process_id, &target_process);
			break;
		case codes::read:
			if (target_process != nullptr)
				status = MmCopyVirtualMemory(target_process, request->target, PsGetCurrentProcess(), request->buffer, request->size, KernelMode, &(request->return_size));
			break;
		case codes::write:
			if (target_process != nullptr)
				status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer, target_process, request->target, request->size, KernelMode, &(request->return_size));
			break;
		default:
			break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}

}
//Real Entry point
NTSTATUS DriverMain(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(registry_path);
	UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\FirstDriver");

	//create device obj.
	PDEVICE_OBJECT device_object = nullptr;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
	if (status != STATUS_SUCCESS)
	{
		debug_print("[-] Failed to create driver device.\n");
		return status;
	}
	debug_print("[+] Driver device created successefully!\n");

	//create device obj.
	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\FirstDriver");
	status = IoCreateSymbolicLink(&symbolic_link, &device_name);
	if (status != STATUS_SUCCESS)
	{
		debug_print("[-] Failed to create driver symbolic link.\n");
		return status;
	}
	debug_print("[+] Driver symbolic link established successefully!\n");

	//Allows to send data between UM and KM
	SetFlag(device_object->Flags, DO_BUFFERED_IO);
	//Setting driver handlers to our functions for UM KM communication
	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_ctl;
	//Device now initialized
	ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

	debug_print("[+] Driver initialized.\n");

	return status;
}
//Fake Entry point
NTSTATUS DriverEntry()
{
	debug_print("[+] Hello!\n");
	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\FirstDriver");
	return IoCreateDriver(&driver_name, &DriverMain);
}