/*
 * Reload driver module for interface awareness.
 * After that, send renewed address to set IP filter again from host (QEMU).
 * 
 * @param svcName Name of the driver to reload
 * @return New base address of reloaded driver
 */
/* These structs are from the source code of the Process Hacker */

#include <psapi.h>
#include <winternl.h>

#define ARRAY_SIZE	        1024

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

LPVOID startAddress = NULL;	// base address of driver
LPVOID endAddress = NULL;	// end address of driver

int kAFL_reload(PTSTR svcName) {
	LPVOID drivers[ARRAY_SIZE];
	DWORD cbNeeded;
	NTSTATUS status;
	int cDrivers, idx = -1;
	int i;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) &&
		cbNeeded < sizeof(drivers)) {
		/* Get list of driver base addresses */
		TCHAR szDriver[ARRAY_SIZE];
		PRTL_PROCESS_MODULES ModuleInfo;

		cDrivers = cbNeeded / sizeof(drivers[0]);

		/* Get all kernel module information */
		ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!ModuleInfo) {
			hprintf("VirtualAlloc failed with error code %lu.\n", GetLastError());
			return 1;
		}
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11,	// 11 -> SystemModuleInformation
			ModuleInfo, 1024 * 1024, NULL);
		if (!NT_SUCCESS(status)) {
			hprintf("NtQuerySystemInformation failed with status code %lu.\n", status);
			VirtualFree(ModuleInfo, 0, MEM_RELEASE);
			return 1;
		}

		for (i = 0; i < cDrivers; i++) {
			/* Find a driver with a same name to argument */
			if (GetDeviceDriverBaseName(drivers[i], szDriver,
				sizeof(szDriver) / sizeof(szDriver[0]))) {
				if (!_tcsncmp(szDriver, svcName, _tcslen(szDriver) - 4)) {
					idx = i;
					break;
				}
			}
		}
		if (idx == -1) {
			hprintf("Failed to find %s. Try loading the driver again.\n", svcName);
			return 1;
		}

		/* Calculate base and end address */
		startAddress = ModuleInfo->Modules[idx].ImageBase;
		endAddress = (LPVOID)((UINT64)startAddress + ModuleInfo->Modules[idx].ImageSize);

		hprintf("startAddress: 0x%llx\n", startAddress);
		hprintf("endAddress: 0x%llx\n", endAddress);

		kAFL_hypercallEx(HYPERCALL_KAFL_RELOAD_COVERED, (uint64_t)startAddress, (uint64_t)endAddress);

		VirtualFree(ModuleInfo, 0, MEM_RELEASE);

        return 0;
	}
	else {
		hprintf("EnumDeviceDrivers failed with error code %lu.\n", GetLastError());
		return 1;
	}
}