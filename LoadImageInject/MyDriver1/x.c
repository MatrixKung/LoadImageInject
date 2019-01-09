#include <ntifs.h>
#include <ntddk.h>
#include "PESTRUCT.h"

extern UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

VOID MyLoadImageNotifyRoutine(
	 PUNICODE_STRING FullImageName,
	 HANDLE ProcessId,
	 PIMAGE_INFO ImageInfo
)
{
	UNICODE_STRING TempString;

	RtlInitUnicodeString(&TempString, L"\\Device\\HarddiskVolume1\\Win32Project1.exe");

	/*KdPrint(("%s\n", (PsGetProcessImageFileName(PsGetCurrentProcess()))));
	if (strstr(PsGetProcessImageFileName(PsGetCurrentProcess()), "LocationNotifi"))
	{*/
		if (!RtlCompareUnicodeString(FullImageName, &TempString, 0))
		{
			KdPrint(("///%wZ\n", FullImageName));
			if (!IsPEFile((ULONG_PTR)ImageInfo->ImageBase))
			{
				KdPrint(("%wZ不是一个PE文件！\n", FullImageName));
				return;
			}

			InjectDll((ULONG_PTR)ImageInfo->ImageBase);
		}
	//}

}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unload Success!\n"));
	PsRemoveLoadImageNotifyRoutine(MyLoadImageNotifyRoutine);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));

	if (Init_NtProtectVirtualMemory() == FALSE)
		return STATUS_UNSUCCESSFUL;

	PsSetLoadImageNotifyRoutine(MyLoadImageNotifyRoutine);
	
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}