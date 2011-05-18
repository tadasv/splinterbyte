#pragma once

#include <windows.h>
#include <eh.h>

extern void SehTranslatorFunction(unsigned int, struct _EXCEPTION_POINTERS *);

class SehGuard {
public:
	SehGuard()
	{
		m_prev = _set_se_translator(SehTranslatorFunction);
	}

	~SehGuard()
	{
		_set_se_translator(m_prev);
	}
private:
	_se_translator_function m_prev;
};


class SehException {
public:
	SehException(unsigned int code) : m_code(code) {};
private:
	unsigned int m_code;
};


bool GetModuleSize(HANDLE hProcess, LPVOID imageBase, DWORD &size);