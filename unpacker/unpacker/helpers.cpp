#include "helpers.h"

void SehTranslatorFunction(unsigned int code, struct _EXCEPTION_POINTERS *)
{
	// here we do loggign or something else.
	throw SehException(code);
}


bool GetModuleSize(HANDLE hProcess, LPVOID imageBase, DWORD &size)
{
	if (hProcess == NULL)
		return false;

	if (imageBase == 0)
		return false;

	bool bFound = false;
	BYTE *queryAddress = (BYTE*)imageBase;
	MEMORY_BASIC_INFORMATION mbi;

	while (!bFound) {
		if (VirtualQueryEx(hProcess, queryAddress, &mbi, sizeof(mbi)) != sizeof(mbi))
			break;
		if (mbi.AllocationBase != imageBase) {
			size = queryAddress - (BYTE*)imageBase;
			bFound = true;
		} else
			queryAddress += mbi.RegionSize;
	}

	return bFound;
}