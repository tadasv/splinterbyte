#include <windows.h>
#include <string.h>
#include <stdio.h>
//#include "malextract.h"
#include "MalwareExtractor.h"

// Ignore MS compiler's warnings about unsafe
// functions.
#pragma warning(disable : 4996)

HINSTANCE hinst;		// Plugin's instance.
HWND hwmain;			// Handle of the OllyDbg main window.
MalwareExtractor me;	// The magic happens here.

BOOL WINAPI DllEntryPoint(HINSTANCE hi, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
		hinst = hi;			// Mark plugin instance
	return 1;				// Report success
}


extc int _export cdecl ODBG_Plugindata(char shortname[32])
{
	// Name of the plugin
	strcpy(shortname, "Malware extractor");
	return PLUGIN_VERSION;
}


extc int _export cdecl ODBG_Plugininit(int ollydbgversion, HWND hw, ulong *features)
{
	// Check that version of OllyDbg is correct.
	if (ollydbgversion < PLUGIN_VERSION)
		return -1;
	// Keep handle of main OllyDbg window. This handle is necessary, for
	// example, to display a message box.
	hwmain = hw;

	Addtolist(0, 0, "Malicious code extraction plugin v1.0");
	Addtolist(0, -1, "  Copyright (C) 2009 Tadas Vilkeliskis");
	Addtolist(0, -1, "  Stevens Institute of Technology");

	return 0;
}


extc int _export cdecl ODBG_Pluginmenu(int origin, char data[4096], void *item)
{
	switch (origin) {
		case PM_MAIN:	// Plugin menu in main window
			strcpy(data, "0 &About");
			return 1;
		case PM_DISASM:	// Disassembly window
			{
				t_dump *p_dump = (t_dump *)item;
				if (p_dump == NULL || p_dump->size == 0)
					// Disassembly window is empty.
					return 0;	
				sprintf(data, "Malware extractor {0 Analyze, 1 Stop analysis}");
				return 1;
			}
	}
	return 0;
}


extc void _export cdecl ODBG_Pluginaction(int origin, int action, void *item)
{
	switch (origin) {
		case PM_MAIN:
			switch (action) {
				case 0:	// Malware extractor -> About
					MessageBox(hwmain,
					"Malicious code extraction plugin v1.0\n(extracts "
					"malicious code from obfuscated binaries)\n "
					"Copyright (C) 2009 Tadas Vilkeliskis\n"
					"Stevens Institute of Technology",
					"Malicious code extraction plugin",
					MB_OK|MB_ICONINFORMATION);
					break;
				default:
					break;
			}
			break;
		case PM_DISASM:
			switch (action) {
				case 0: // Malware extractor -> Analyze
					{
						HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
						char dllName[] = "c:\\Documents and Settings\\T\\Desktop\\research\\unpacker\\release\\unpacker.dll";
						HANDLE hProcess = (HANDLE) Plugingetvalue(VAL_HPROCESS);
						LPVOID addrDll = VirtualAllocEx(hProcess, NULL, sizeof(dllName), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

						WriteProcessMemory(hProcess, addrDll, dllName, sizeof(dllName), NULL);
						HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
							(LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"),
							addrDll, NULL, NULL);

						ResumeThread(hThread);

						//WaitForSingleObject(hThread, INFINITE);

						return;
						if (me.IsRunning()) {
							Error("Malware extractor is already running");
							return;
						}

						if (me.Initialize() == -1) {
							switch (me.GetErrorCode()) {
								case ME_ERROR_NOTHREAD:
									Error("No threads found.");
									break;
								case ME_ERROR_MEMALLOC:
									Error("Failed to allocate memory.");
									break;
								case ME_ERROR_MEMREAD:
									Error("Failed to read process memory.");
									break;
							}
							me.Reset();
							return;
						}
						return;

						if (me.FindNextAddress(0) == -1) {
							switch (me.GetErrorCode()) {
								case ME_ERROR_OUTOFBOUNDS:
									Error("Trying to access illegal address.");
									break;
								case ME_ERROR_NOTFOUND:
									Error("Address not found.");
									break;
							}
							me.Reset();
							return;
						}

						//sprintf (str, "FINAL: %d, %08X, %08X", cmd_size, dasm.jmpaddr, ip - cmd_size);
						//Error (str);
						/*if (Setbreakpointext (ip - cmd_size, TY_ONESHOT, 0, 0) == -1) {
							ODBG_Pluginreset ();
							Error ("Cannot set breakpoint on %08X", ip - cmd_size);
							return;
						}*/

						//Go (me_ctx.thread->threadid, ip - cmd_size, STEP_SKIP, 1, 1);

						//Error ("%08X", ip - cmd_size);
					}
					break;
				case 1: // Malware extractor -> Stop analysis
					//Suspendprocess (0);
					ODBG_Pluginreset ();
					break;
			}
			break;
	}
}


void ODBG_Pluginreset(void)
{
	me.Reset();
}

// Callback function called each time bebug event happens. 
int ODBG_Pausedex(int reason, int extdata, t_reg *reg, DEBUG_EVENT *debugevent)
{
	if (/*me_ctx.invoked == */1) {
		switch (reason & PP_MAIN) {
			case PP_EVENT:
				if (reason & PP_INT3BREAK) {
					/*t_disasm dasm;
					unsigned char buf[MAXCMDSIZE + 1];

					Readmemory (buf, reg->ip, MAXCMDSIZE, MM_RESTORE);
					//Error ("%02x%02x%02x%02x", buf[0], buf[1], buf[2], buf[3]);
					Disasm (buf, MAXCMDSIZE, reg->ip, NULL, &dasm, DISASM_ALL, me_ctx.thread->threadid);
					//Error ("%08x, %08x == %08x", dasm.cmdtype, dasm.ip, reg->ip);
					Readmemory (buf, dasm.jmpaddr, MAXCMDSIZE, MM_RESTORE);
					//Error ("%d, %08x %08x", dasm.jmpaddr - me_ctx.module->base, dasm.jmpaddr, me_ctx.module->base);
					if (memcmp ((void*)buf, (void*)&me_ctx.imagecopy[dasm.jmpaddr - me_ctx.module->base], MAXCMDSIZE) == 0) {
						unsigned char *ptr = &me_ctx.imagecopy[dasm.jmpaddr - me_ctx.module->base];
						ulong total = 0;
						ulong cmd_size;
						ulong ip = dasm.jmpaddr;
						dasm.cmdtype = 0;

						while (dasm.cmdtype < 0x50 || dasm.cmdtype > 0x80) {
							cmd_size = Disasm (ptr, MAXCMDSIZE, ip, NULL, &dasm, DISASM_ALL,
												me_ctx.thread->threadid);
							total += cmd_size;
							ptr += cmd_size;
							ip += cmd_size;
						}

						if (Setbreakpointext (ip - cmd_size, TY_ONESHOT, 0, 0) == -1) {
							ODBG_Pluginreset ();
							Error ("Cannot set breakpoint on %08X", dasm.jmpaddr);
							return 1;
						}

						//Go (me_ctx.thread->threadid, ip - cmd_size, STEP_SKIP, 1, 1);
						//Error ("BP at %08X", ip-cmd_size);
					} else {
						Error ("OEP: %08X", dasm.jmpaddr);
						ODBG_Pluginreset ();
						return 0;
					}*/
				}
				break;
			case PP_PAUSE:
				break;
			case PP_TERMINATED:
				ODBG_Pluginreset ();
				return 0;
				break;
		}
	}
	return 1;
}