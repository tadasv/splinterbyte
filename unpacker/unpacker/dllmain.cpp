// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

extern PBYTE EmitJump(PBYTE pbCode, PBYTE pbJumpTo);
void Dispatcher();

// Original functions we are going to hook.

_pvf TrueBaseThreadStart;
_NtContinue TrueNtContinue = (_NtContinue)GetProcAddress(GetModuleHandle("ntdll"), "NtContinue");
_KiUserExceptionDispatcher TrueKiUserExceptionDispatcher =
	(_KiUserExceptionDispatcher)GetProcAddress(GetModuleHandle("ntdll"), "KiUserExceptionDispatcher");

/////////////////////////////////

//FILE *fLog;
FILE *f;
BlockBuilder bb;
PBYTE pRCAddress;
PBYTE pContinueAddress;
PBYTE pNextInstruction;
BYTE backup[5];
BYTE dispatchType;

PVOID pStack;
DWORD stackSize = 0x2000; // Two pages should be enough
DWORD trueStackLimit;
DWORD trueStackBase;

char buff[25];

CONTEXT currentContext;

#define DISPATCH_DEFAULT 0
#define DISPATCH_FIRSTTIME 1
#define DISPATCH_NTCONTINUE 2

CRITICAL_SECTION critical_section;



/////////////////////////////////


VOID NTAPI FakeKiUserExceptionDispatcher(PCONTEXT Context, EXCEPTION_RECORD ExceptionRecord)
{
/*
	f = fopen("c:\\packlog.txt", "a");
	fprintf(f, "\nKiUserExceptionDispatcher\n");
	fprintf(f, "             EAX:%08X EBX:%08X ECX:%08X EDX:%08X\n", Context->Eax, Context->Ebx, Context->Ecx, Context->Edx);
	fprintf(f, "             ESI:%08X EDI:%08X ESP:%08X EBP:%08X\n", Context->Esi, Context->Edi, Context->Esp, Context->Ebp);
	fprintf(f, "             EIP:%08X FLG:%08X\n", Context->Eip, Context->EFlags);
	fprintf(f, "             CS:%04X DS:%04X FS:%04X ES:%04X SS:%04X GS:%04X\n", Context->SegCs, Context->SegDs, Context->SegFs, Context->SegEs, Context->SegSs, Context->SegGs); 
	fprintf(f, "             Exception address: %08X\n", ExceptionRecord.ExceptionAddress);
	fprintf(f, "             Exception code: %08X\n", ExceptionRecord.ExceptionCode);
	fprintf(f, "             Exception flags: %d\n", ExceptionRecord.ExceptionFlags);
*/
	
	_asm pushad;
	_asm pushfd;

	DWORD exceptionHandler;

	// Obtain the address of exception handler.
	_asm push eax;
	_asm mov eax, fs:[0];
	_asm add eax, 4;
	_asm mov eax, [eax];
	_asm mov exceptionHandler, eax;
	_asm pop eax;

	ExceptionRecord.ExceptionAddress =
		(PVOID)((PBYTE)ExceptionRecord.ExceptionAddress - (PBYTE)bb.GetBBAddress()
				+ (DWORD) pNextInstruction);

	//f = fopen("c:\\packlog.txt", "a");
	//fprintf(f, "SEH %08X\n", exceptionHandler);
	//fprintf(f, "EX ADDR %08X\n", ExceptionRecord.ExceptionAddress);
	//fclose(f);

	/*if (exceptionHandler == 0x4141d0) {
		MessageBox(NULL, "Attach now", "aa", MB_OK);
	}*/

	if (dispatchType == DISPATCH_FIRSTTIME) {
		CopyMemory(pRCAddress, backup, 5);
	}
	
	pRCAddress = (PBYTE)exceptionHandler;
	CopyMemory(backup, pRCAddress, 5);
	EmitJump(pRCAddress, (PBYTE)Dispatcher);
	dispatchType = DISPATCH_FIRSTTIME;

	/*f = fopen("c:\\packlog.txt", "a");
	fprintf(f, "SEH AT %08X %08X\n", ExceptionRecord.ExceptionAddress, exceptionHandler);
	fflush(f);
	fclose(f);*/

	if (ExceptionRecord.ExceptionAddress == (PVOID)0x7C90EC3A)
		bb.WriteLog();



	_asm popfd;
	_asm popad;
	_asm mov esp, ebp;
	_asm pop ebp;
	_asm jmp TrueKiUserExceptionDispatcher;
}


NTSTATUS __declspec(naked) NTAPI FakeNtContinue(PCONTEXT Context, BOOL TestAlert)
{
	_asm push ebp;
	_asm mov ebp, esp;
	_asm pushad;

	EnterCriticalSection(&critical_section);

	{
		if ((Context->Eip != 0x7c810705) && (Context->Eip != 0x7c951e13)) { // 0001 (0001)  0:**** kernel32!BaseProcessStartThunk
			if (dispatchType == DISPATCH_FIRSTTIME)
				CopyMemory(pRCAddress, backup, 5);
			//f = fopen("c:\\packlog.txt", "a");
			//fprintf(f, "NTCONTINUE %08X\n", Context->Eip);
			//fflush(f);
			//fclose(f);
			pRCAddress = (PBYTE)Context->Eip;
			Context->Eip = (DWORD)Dispatcher;
			dispatchType = DISPATCH_NTCONTINUE;
		}
	}

	LeaveCriticalSection(&critical_section);

	_asm popad;
	_asm mov esp, ebp;
	_asm pop ebp;

	_asm jmp TrueNtContinue;
}


VOID FakeBaseThreadStart()
{
	DWORD tmp;

	_asm mov	tmp, eax
	_asm pushad;
	_asm pushfd;

//	EnterCriticalSection(&critical_section);

	f = fopen("c:\\packlog.txt", "a");
	fprintf(f, "\nNew thread started\n");
	fprintf(f, "Thread func: %08X\n", tmp);

	_asm mov	eax, fs:[0x24];
	_asm mov	tmp, eax;

	fprintf(f, "Thread ID: %08X\n", tmp);
	fclose(f);

	_asm popfd;
	_asm popad;

//	LeaveCriticalSection(&critical_section);

	return TrueBaseThreadStart();
}


/*
 * The dispatcher should never return, therefore it should
 * be entered only from instrumentation code.
 */
void __declspec(naked) Dispatcher()
{
	// Save CPU state
	_asm {
		mov   currentContext.Eax, eax;
		mov   currentContext.Ebx, ebx;
		mov   currentContext.Ecx, ecx;
		mov   currentContext.Edx, edx;
		mov   currentContext.Esi, esi;
		mov   currentContext.Edi, edi;
		mov   currentContext.Ebp, ebp;
		mov   currentContext.Esp, esp;
		push  eax;
		pushfd;
		mov   eax, [esp];
		mov   currentContext.EFlags, eax;
		add   esp, 4;
		
		// Get linear address of TEB.
		mov    eax, fs:[0x18];
		push   ebx;
		// Save and set new stack base.
		mov    ebx, [eax + 0x4];
		mov    trueStackBase, ebx;
		lea    ebx, [eax + 0x4];
		push   eax;
		mov    eax, pStack;
		add    eax, stackSize;
		mov    [ebx], eax;
		pop    eax;
		// Save and set new stack limit
		mov    ebx, [eax + 0x8];
		mov    trueStackLimit, ebx;
		lea    ebx, [eax + 0x8];
		mov    eax, pStack;
		mov    [ebx], eax;

		pop eax;
		mov esp, fs:[0x4];
	}

	//_asm push ebp;
	_asm mov ebp, esp;
	_asm pushad;

	switch (dispatchType) {
		case DISPATCH_FIRSTTIME:
			CopyMemory(pRCAddress, backup, 5);
		case DISPATCH_NTCONTINUE:
			dispatchType = DISPATCH_DEFAULT;
			pNextInstruction = pRCAddress;
			if (!bb.BuildBlock(pNextInstruction, currentContext)) {
				MessageBox(NULL, "Buildblock failed", "ERROR", MB_OK);
			}
			break;
		default:
			{
				pNextInstruction = bb.GetNextInstructionAddress();
				if (!bb.BuildBlock(pNextInstruction, currentContext)) {
					MessageBox(NULL, "Buildblock failed", "ERROR", MB_OK);
				}
			}
			break;
	}

	{
		
	}

	pContinueAddress = (PBYTE)bb.GetBBAddress();

	//LeaveCriticalSection(&critical_section);

	//_asm popfd;
	_asm popad;

	_asm {
		// Restore TEB
		mov    eax, fs:[0x18];
		lea    ebx, [eax + 0x4];
		push   eax;
		mov    eax, trueStackBase;
		mov    [ebx], eax;
		pop    eax;
		lea    ebx, [eax + 0x8];
		mov    eax, trueStackLimit;
		mov    [ebx], eax;
		// Restore CPU state
		sub		esp, 4;
		mov		eax, currentContext.EFlags;
		mov		[esp], eax;
		popfd
		mov		eax, currentContext.Eax;
		mov		ebx, currentContext.Ebx;
		mov		ecx, currentContext.Ecx;
		mov		edx, currentContext.Edx;
		mov		esi, currentContext.Esi;
		mov		edi, currentContext.Edi;
		mov		ebp, currentContext.Ebp;
		mov		esp, currentContext.Esp;

		jmp pContinueAddress;
	}
	//_asm ret
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			HMODULE hModule;
			PIMAGE_DOS_HEADER pDos;
			PIMAGE_NT_HEADERS32 pNt;
			PBYTE ptr;
			DISASSEMBLER dis;
			INSTRUCTION *pIns;
			DWORD moduleSize;
			DWORD oldProtect;


			MessageBox(NULL, "Attach debugger now if needed", "Information", MB_OK);


			#ifdef _M_IX86
			ARCHITECTURE_TYPE arch = ARCH_X86;
			#elif defined _M_X64
			ARCHITECTURE_TYPE arch = ARCH_X64;
			#else
			#error unsupported platform
			#endif

			hModule = GetModuleHandle("ntdll");
			if (!GetModuleSize(GetCurrentProcess(), (LPVOID)hModule, moduleSize)) {
				MessageBox(NULL, "Couldn't get size of ntdll.", "Error", MB_OK | MB_ICONERROR);
				return FALSE;
			}
			VirtualProtect(hModule, moduleSize, PAGE_EXECUTE_READWRITE, &oldProtect);

			hModule = GetModuleHandle("kernel32");
			if (!GetModuleSize(GetCurrentProcess(), (LPVOID)hModule, moduleSize)) {
				MessageBox(NULL, "Couldn't get size of kernel32.", "Error", MB_OK | MB_ICONERROR);
				return FALSE;
			}
			VirtualProtect(hModule, moduleSize, PAGE_EXECUTE_READWRITE, &oldProtect);

			hModule = GetModuleHandle(NULL);
			if (!GetModuleSize(GetCurrentProcess(), (LPVOID)hModule, moduleSize)) {
				MessageBox(NULL, "Couldn't get size of self.", "Error", MB_OK | MB_ICONERROR);
				return FALSE;
			}
			VirtualProtect(hModule, moduleSize, PAGE_EXECUTE_READWRITE, &oldProtect);

			pDos = (PIMAGE_DOS_HEADER) hModule;
			pNt = (PIMAGE_NT_HEADERS32)((BYTE*)pDos + pDos->e_lfanew);
			
			InitializeCriticalSection(&critical_section);
			// Install jump at entry point.
			EnterCriticalSection(&critical_section);
			pRCAddress = (PBYTE)hModule + pNt->OptionalHeader.AddressOfEntryPoint;
			CopyMemory((PBYTE)backup, (PBYTE)pRCAddress, 5);
			LeaveCriticalSection(&critical_section);
			EmitJump((PBYTE)pRCAddress, (PBYTE)Dispatcher);
			dispatchType = DISPATCH_FIRSTTIME;

			// Get the location of BaseThreadStart and hook it.
			ptr = (PBYTE) GetProcAddress(GetModuleHandle("kernel32"), "CreateThread");
			if (!InitDisassembler(&dis, arch)) {
				MessageBox(NULL, "Couldn't initialize disassembler.", "Error", MB_OK | MB_ICONERROR);
				return FALSE;
			}

			pIns = GetInstruction(&dis, (ULONG_PTR)ptr, ptr, DISASM_DECODE | DISASM_DISASSEMBLE);
			while (pIns && (pIns->Type != ITYPE_RET)) {
				ptr += pIns->Length;
				pIns = GetInstruction(&dis, (ULONG_PTR)ptr, ptr, DISASM_DECODE | DISASM_DISASSEMBLE);
			}

			if (!pIns) {
				MessageBox(NULL, "Couldn't find address of BaseThreadStartThunk.", "Error", MB_OK | MB_ICONERROR);
				return FALSE;
			}

			// Don't forget to add RET instruction length.
			ptr += pIns->Length;
			CloseDisassembler(&dis);
			TrueBaseThreadStart = (_pvf) ptr;

			pStack = VirtualAlloc(NULL, stackSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if (pStack == NULL) {
				MessageBox(NULL, "Couldn't allocate stack memory.", "Error", MB_OK | MB_ICONERROR);
			}


	/*
			Mhook_SetHook((PVOID*)&TrueBaseThreadStart, FakeBaseThreadStart);*/
			Mhook_SetHook((PVOID*)&TrueNtContinue, FakeNtContinue);
			Mhook_SetHook((PVOID*)&TrueKiUserExceptionDispatcher, FakeKiUserExceptionDispatcher);
			
		}
		break;
	case DLL_PROCESS_DETACH:
		{/*
			Mhook_Unhook((PVOID*)&TrueBaseThreadStart);*/
			Mhook_Unhook((PVOID*)&TrueNtContinue);
			Mhook_Unhook((PVOID*)&TrueKiUserExceptionDispatcher);
			if (pStack != NULL)
				VirtualFree(pStack, NULL, MEM_RELEASE);
			DeleteCriticalSection(&critical_section);
		}
		break;
	}
	return TRUE;
}

