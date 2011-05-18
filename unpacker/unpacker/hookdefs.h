#pragma once


typedef NTSTATUS (NTAPI * _NtContinue)(PCONTEXT Context, BOOL TestAlert);
typedef VOID (NTAPI * _KiUserExceptionDispatcher)(PCONTEXT Context,
												  EXCEPTION_RECORD ExceptionRecord);
typedef VOID (* _pvf)();