// injector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc < 3) {
		printf("Usage: injector <command line> <path to dll>\n");
		return -1;
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	HMODULE hKernel32;
	HANDLE hRemoteThread;
	
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	// Create suspended process
	if(!CreateProcess(NULL,
		argv[1],
		NULL,
		NULL,
		FALSE,
		CREATE_NEW_CONSOLE | CREATE_SUSPENDED | NORMAL_PRIORITY_CLASS,
		NULL,
		NULL,
		&si, &pi))
	{
		printf("EE CreateProcess() failed. Error: %u\n", GetLastError());
		return -1;
	}

	printf("II %s\n", argv[1]);
	printf("II PID: %u\n", pi.dwProcessId);
	printf("II TID: %u\n", pi.dwThreadId);

	// Prepare process for DLL injection
	LPVOID pFilename = VirtualAllocEx(pi.hProcess, NULL, strlen(argv[2]) + 1,
						MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (pFilename == NULL) {
		printf("EE VirtualAllocEx() failed. Error: %u\n", GetLastError());
		if (!TerminateProcess(pi.hProcess, 0))
			printf("EE TerminateProcess() failed. Error: %u\n", GetLastError());
		return -1;
	}
	
	if (!GetModuleHandleEx(0, "kernel32.dll", &hKernel32)) {
		printf("EE GetModuleHandleEx() failed. Error: %u\n", GetLastError());
		goto cleanup;
	}

	if (!WriteProcessMemory(pi.hProcess, pFilename, argv[2], strlen(argv[2]), NULL)) {
		printf("EE WriteProcessMemory() failed. Error: %u\n", GetLastError());
		goto cleanup;
	}

	// inject DLL
	hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, NULL,
					(LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"),
					pFilename, NULL, NULL);
	if (hRemoteThread == NULL) {
		printf("EE CreateRemoteThread() failed. Error: %u\n", GetLastError());
		goto cleanup;
	}

	printf("II Waiting for remote thread to terminate.\n");
	WaitForSingleObject(hRemoteThread, INFINITE);

	HMODULE hInjection;
	if (!GetExitCodeThread(hRemoteThread, (LPDWORD)&hInjection)) {
		printf("EE GetExitCodeThread() failed. Error %u\n", GetLastError());
		goto cleanup;
	}

	if (hInjection == NULL) {
		printf("EE DLL injection failed\n");
		goto cleanup;
	} else {
		printf("II Injection base. %08x\n", hInjection);
	}

	printf("II DLL injection was successful.\n");

	if (!VirtualFreeEx(pi.hProcess, pFilename, 0, MEM_RELEASE))
		printf("EE VirtualFreeEx() failed. Error %u\n", GetLastError());
	pFilename = NULL;

	if (ResumeThread(pi.hThread) == -1) {
		printf("EE ResumeThread() failed. Error: %u\n", GetLastError());
	}

	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);
	if (hKernel32)
		FreeLibrary(hKernel32);
	return 0;

cleanup:		
	if (pFilename != NULL)
		VirtualFreeEx(pi.hProcess, pFilename, 0, MEM_RELEASE);
	if (!TerminateProcess(pi.hProcess, 0))
			printf("EE TerminateProcess() failed. Error: %u\n", GetLastError());
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);
	if (hKernel32)
		FreeLibrary(hKernel32);
	return -1;
}
