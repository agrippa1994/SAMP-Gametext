#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Psapi.lib")

#include "Windows.h"
#include "Hook.h"
#include "Pattern.h"

#include <Psapi.h>
#include <detours.h>
#include <ShlObj.h>

#include <fstream>
#include <string>

CHook<CCallConvention::stdcall_t, void, char *, int, int> g_showGameTextHook;

HANDLE g_hDllHandle = INVALID_HANDLE_VALUE;


DWORD GetModuleLen(HMODULE hMod)
{
	MODULEINFO info;
	GetModuleInformation(GetCurrentProcess(), hMod, &info, sizeof(info));
	return info.SizeOfImage;
}

void init()
{
	DWORD dwSAMP = NULL;
	while ((dwSAMP = DWORD(GetModuleHandleA("samp.dll"))) == NULL)
		Sleep(100);


	DWORD dwCall = FindPattern(dwSAMP, GetModuleLen((HMODULE) dwSAMP), (BYTE *)
		"\x55\x8B\xEC\x81\x7D\x10\xC8\x00\x00\x00\x7F\x36\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x4D\x08\x8B\x15\x00\x00\x00\x00\x83",
		"xxxxxxxxxxxxx????x????xxxxx????x");

	if (!dwCall)
	{
		MessageBeep(0);
		return;
	}

	g_showGameTextHook.apply(dwCall, [](char *szString, int uk1, int uk2)
	{
		char szFilePath[MAX_PATH + 1] = { 0 };

		SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, szFilePath);
		strcat_s(szFilePath, "\\GTA San Andreas User Files\\SAMP\\gametexts.txt");

		std::fstream stream(szFilePath, std::ios_base::app);
		if (stream.is_open())
		{
			stream << szString << std::endl;
			stream.close();
		}

		return g_showGameTextHook.callOrig(szString, uk1, uk2);
	});

	return;
}


BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReasonForCall, LPVOID pVoid)
{
	DisableThreadLibraryCalls((HMODULE) hInstance);

	if (dwReasonForCall != DLL_PROCESS_ATTACH)
		return FALSE;

	g_hDllHandle = (HMODULE) hInstance;

	char szBuffer[MAX_PATH + 1] = { 0 };
	GetModuleFileNameA(NULL, szBuffer, sizeof(szBuffer) -1);

	DWORD dwPID = 0;
	GetWindowThreadProcessId(FindWindowA(0, "GTA:SA:MP"), &dwPID);
	
	if (dwPID == GetCurrentProcessId())
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE) init, 0, 0, NULL);
	
	return TRUE;
}

extern "C" __declspec(dllexport) int Load()
{
	char szDLLPath[MAX_PATH + 1] = { 0 };
	DWORD dwPId = 0;
	BOOL bRetn;

	GetModuleFileNameA((HMODULE) g_hDllHandle, szDLLPath, sizeof(szDLLPath));

	HWND hWnd = FindWindowA(0, "GTA:SA:MP");
	if (hWnd == NULL)
		return 0;

	GetWindowThreadProcessId(hWnd, &dwPId);
	if (dwPId == 0)
		return 0;

	HANDLE hHandle = OpenProcess((STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF), FALSE, dwPId);
	if (hHandle == 0 || hHandle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	void *pAddr = VirtualAllocEx(hHandle, NULL, strlen(szDLLPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddr == NULL)
	{
		CloseHandle(hHandle);
		return 0;
	}

	bRetn = WriteProcessMemory(hHandle, pAddr, szDLLPath, strlen(szDLLPath) + 1, NULL);
	if (bRetn == FALSE)
	{
		VirtualFreeEx(hHandle, pAddr, strlen(szDLLPath) + 1, MEM_RELEASE);
		CloseHandle(hHandle);
		return 0;
	}

	LPTHREAD_START_ROUTINE pFunc = (LPTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (pFunc == NULL)
	{
		VirtualFreeEx(hHandle, pAddr, strlen(szDLLPath) + 1, MEM_RELEASE);
		CloseHandle(hHandle);
		return 0;
	}

	HANDLE hThread = CreateRemoteThread(hHandle, 0, 0, pFunc, pAddr, 0, 0);
	if (hThread == NULL || hThread == INVALID_HANDLE_VALUE)
	{
		VirtualFreeEx(hHandle, pAddr, strlen(szDLLPath) + 1, MEM_RELEASE);
		CloseHandle(hHandle);
		return 0;
	}

	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hHandle, pAddr, strlen(szDLLPath) + 1, MEM_RELEASE);

	DWORD dwExitCode = 0;
	if (!GetExitCodeThread(hThread, &dwExitCode))
		return 0;

	CloseHandle(hThread);

	return dwExitCode;
}