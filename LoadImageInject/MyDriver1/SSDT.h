#ifndef SSDTHOOK_H
#define SSDTHOOK_H

#define IndexOfNtProtectVirtualMemory 77

typedef struct _SYSTEM_SERVICE_TABLE
{
	PLONG ServiceTableBase;
	PLONG ServiceCounterTableBase;
	UINT64 NumberOfServices;
	PUCHAR ParamTableBase;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

typedef struct _USER_PROTECT_MEMORY
{
	PVOID	  ProtectBase;
	ULONG_PTR ProtectSize;
	ULONG	  OldProtectAccess;
}USER_PROTECT_MEMORY, *PUSER_PROTECT_MEMORY;

typedef NTSTATUS (*PFN_NTPROTECTVIRTUALMEMORY)(IN HANDLE ProcessHandle,
IN OUT PVOID *UnsafeBaseAddress,
IN OUT SIZE_T *UnsafeNumberOfBytesToProtect,
IN ULONG NewAccessProtection,
OUT PULONG UnsafeOldAccessProtection);

PFN_NTPROTECTVIRTUALMEMORY NtProtectVirtualMemory;

ULONG_PTR GetSsdtBase()
{
	ULONG_PTR SystemCall64;								//从msr中读取到的SystemCall64的地址
	ULONG_PTR StartAddress;								//搜寻的起始地址就是SystemCall64的起始地址
	ULONG_PTR EndAddress;								//搜寻的终结地址
	UCHAR *p;											//用来判断的特征码
	ULONG_PTR SsdtBast = 0;								//SSDT基址

	SystemCall64 = __readmsr(0xC0000082);
	StartAddress = SystemCall64;
	EndAddress = StartAddress + 0x500;
	while (StartAddress < EndAddress)
	{
		p = (UCHAR*)StartAddress;
		if (MmIsAddressValid(p) && MmIsAddressValid(p + 1) && MmIsAddressValid(p + 2))
		{
			if (*p == 0x4c && *(p + 1) == 0x8d && *(p + 2) == 0x15)
			{
				SsdtBast = (ULONG_PTR)(*(ULONG*)(p + 3)) + (ULONG_PTR)(p + 7);
				break;
			}
		}
		++StartAddress;
	}

	return SsdtBast;
}

ULONG_PTR GetFuncAddress(PWSTR FuncName)
{
	UNICODE_STRING uFunctionName;
	RtlInitUnicodeString(&uFunctionName, FuncName);
	return (ULONG_PTR)MmGetSystemRoutineAddress(&uFunctionName);
}

BOOLEAN Init_NtProtectVirtualMemory()
{
	PSYSTEM_SERVICE_TABLE SsdtInfo;
	LONG Offset;

	SsdtInfo = (PSYSTEM_SERVICE_TABLE)GetSsdtBase();
	if (SsdtInfo == NULL)
		return FALSE;

	Offset = SsdtInfo->ServiceTableBase[IndexOfNtProtectVirtualMemory];
	NtProtectVirtualMemory = (PFN_NTPROTECTVIRTUALMEMORY)((ULONG_PTR)SsdtInfo->ServiceTableBase + (ULONG_PTR)(Offset >> 4));
	if (NtProtectVirtualMemory == NULL)
		return FALSE;

	return TRUE;
}

BOOLEAN Local_ProtectVirtualMemory(IN OUT PVOID UnsafeBaseAddress,
	IN OUT SIZE_T UnsafeNumberOfBytesToProtect,
	IN ULONG NewAccessProtection)
{
	NTSTATUS status;
	ULONG_PTR RegionSize;
	PUSER_PROTECT_MEMORY UserProtectMemroy = NULL;

	RegionSize = sizeof(USER_PROTECT_MEMORY);

	/*因为在内核调用Nt系列的函数会检查参数的地址是否是应用层的（如果Previous不是UserMode），
	所以这里分配一片应用层的内存来保存参数*/
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID)&UserProtectMemroy, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("AllocateMemory Fail!\n"));
		return FALSE;
	}

	UserProtectMemroy->ProtectBase = UnsafeBaseAddress;
	UserProtectMemroy->ProtectSize = UnsafeNumberOfBytesToProtect;
	UserProtectMemroy->OldProtectAccess = 0;

	status = NtProtectVirtualMemory(NtCurrentProcess(), &UserProtectMemroy->ProtectBase, &UserProtectMemroy->ProtectSize, NewAccessProtection, &UserProtectMemroy->OldProtectAccess);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ProtectMemory Fail!\n"));
		return FALSE;
	}

	return TRUE;
}

#endif