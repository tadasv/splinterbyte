#pragma once

#include <vector>
#include <windows.h>
#include "disasm-lib/disasm.h"

#define EFLAGS_CF 1
#define EFLAGS_PF (1 << 2)
#define EFLAGS_ZF (1 << 6)
#define EFLAGS_SF (1 << 7)
#define EFLAGS_OF (1 << 11)

#define MODRM_MOD_MASK (3 << 6)
#define MODRM_REG_MASK (7 << 3)
#define MODRM_RM_MASK (7)

#define REG_EAX 0
#define REG_ECX 1
#define REG_EDX 2
#define REG_EBX 3
#define REG_ESP 4
#define REG_EBP 5
#define REG_ESI 6
#define REG_EDI 7


typedef struct _BASICBLOCK
{
	DWORD startAddress;
	DWORD size;
	DWORD checksum;
	DWORD executionCount;
} BASIC_BLOCK, *PBASIC_BLOCK;


class BlockBuilder
{
public:
	BlockBuilder();
	~BlockBuilder();
	bool BuildBlock(PBYTE startAddress, CONTEXT &ctx);
	PVOID GetBBAddress();
	DWORD GetCodeSize();
	PBYTE GetNextInstructionAddress();
	std::vector<BASIC_BLOCK>::iterator FindBasicBlock(DWORD startAddress);

	void BlockBuilder::WriteLog();

private:
	bool IsContidionalBranchTaken(BYTE opcode[2], CONTEXT ctx);
	DWORD GetIndirectCallAddress(PBYTE operands, CONTEXT ctx);
	BYTE GetMod(BYTE modrm);
	BYTE GetRM(BYTE modrm);
	BYTE GetReg(BYTE modrm);
	BYTE GetScale(BYTE sib);
	BYTE GetIndex(BYTE sib);
	BYTE GetBase(BYTE sib);
	DWORD GetAddressFromSib(BYTE mod, PBYTE sib, PCONTEXT ctx);
private:
	PBYTE m_code;
	PBYTE m_pNextInstruction;
	DISASSEMBLER m_dis;
	DWORD m_codeSize;
	FILE *m_fLog;
	std::vector<BASIC_BLOCK> m_basicBlocks;
};