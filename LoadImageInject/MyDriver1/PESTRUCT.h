#pragma once
#ifndef _PESTRUCT_H
#define _PESTRUCT_H

#include <ntimage.h>
#include "SSDT.h"

BOOLEAN IsPEFile(ULONG_PTR ImageBase)
{
	IMAGE_DOS_HEADER * DosHeader = (IMAGE_DOS_HEADER *)ImageBase;
	if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		IMAGE_NT_HEADERS64 *NtHeader = (IMAGE_NT_HEADERS64 *)(ImageBase + DosHeader->e_lfanew);
		if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
			return TRUE;
	}

	return FALSE;
}

/*在模块回调中，除了进程主模块加载的时候，在其他模块的时候进程会在Eprocess中上锁，之后再操作该进程内存（分配读取写入）的时候也会加锁，因此会有死锁现象*/
VOID InjectDll(ULONG_PTR ImageBase)
{
	IMAGE_DOS_HEADER * DosHeader = (IMAGE_DOS_HEADER *)ImageBase;
	IMAGE_NT_HEADERS64 *NtHeader = (IMAGE_NT_HEADERS64 *)(ImageBase + DosHeader->e_lfanew);
	NTSTATUS status;
	PVOID AllocateBase = NULL;						//ImageBase + NtHeader->OptionalHeader.SizeOfImage
	ULONG_PTR RegionSize = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);		//先查看当前有多少个IMAGE_IMPORT_DESCRIPTOR
	RegionSize = (RegionSize + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);																		//增加一个我们自身的内存
	RegionSize = RegionSize + 0x82c;																										//用来分配路径等字符串的内容

	for (ULONG i = 0; i < 1000; ++i)
	{
		AllocateBase = (PVOID)(ImageBase + (i << 12));

		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &AllocateBase, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (NT_SUCCESS(status))
			break;
	}

	RtlZeroMemory(AllocateBase, RegionSize);													//清空内存

	RtlCopyMemory((PVOID)((ULONG_PTR)AllocateBase + sizeof(IMAGE_IMPORT_DESCRIPTOR)),
		(PVOID)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + ImageBase),
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);				//拷贝内存

	IMAGE_THUNK_DATA64 *ThunkData = (IMAGE_THUNK_DATA64 *)((ULONG_PTR)AllocateBase +
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size + 0x830);		//0x830就是分配地址的末尾减去两个IMAGE_THUNK_DATA的位置
	ThunkData->u1.Function = 0x8000000000000001;												//倒数一个为NULL表示结尾，倒数第二个为0x8000000000000001

	strcpy(((char *)(ULONG_PTR)AllocateBase + sizeof(IMAGE_IMPORT_DESCRIPTOR) + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size), "C:\\Users\\t.dll");

	//接下来初始化我们自身的IMAGE_IMPORT_DESCRIPTOR
	IMAGE_IMPORT_DESCRIPTOR *MyImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)AllocateBase;
	MyImportDescriptor->FirstThunk = (ULONG)((ULONG_PTR)ThunkData - ImageBase);
	MyImportDescriptor->OriginalFirstThunk = (ULONG)((ULONG_PTR)ThunkData - ImageBase);
	MyImportDescriptor->Name = (ULONG)((ULONG_PTR)AllocateBase + sizeof(IMAGE_IMPORT_DESCRIPTOR) + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size - ImageBase);

	//这里不可以使用直接修改CR0来修改内存
	//因为如果直接修改CR0，这里修改的是物理页面的内容，而不是映射过来的虚拟地址
	//之后的加载都会崩掉
	if (Local_ProtectVirtualMemory(&NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT], 8, PAGE_EXECUTE_READWRITE))
	{
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = (ULONG)((ULONG_PTR)MyImportDescriptor - ImageBase);
	}
	if (Local_ProtectVirtualMemory(&NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT], 8, PAGE_EXECUTE_READWRITE))
	{
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	}
}

#endif
