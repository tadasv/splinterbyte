#include "BlockBuilder.h"

// This function is defined in mhook.cpp.
extern PBYTE EmitJump(PBYTE pbCode, PBYTE pbJumpTo);
extern void Dispatcher();
extern NTSTATUS NTAPI FakeNtContinue(PCONTEXT Context, BOOL TestAlert);


void BlockBuilder::WriteLog()
{
	std::vector<BASIC_BLOCK>::iterator it;
	for (it = m_basicBlocks.begin(); it != m_basicBlocks.end(); it++)
	fprintf(m_fLog, "%08X %d %d\n", it->startAddress, it->executionCount, it->size);
	fflush(m_fLog);
}


BlockBuilder::BlockBuilder()
{
	#ifdef _M_IX86
	ARCHITECTURE_TYPE arch = ARCH_X86;
	#elif defined _M_X64
	ARCHITECTURE_TYPE arch = ARCH_X64;
	#else
	#error unsupported platform
	#endif

	m_pNextInstruction = NULL;
	m_code = (PBYTE) VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	InitDisassembler(&m_dis, arch);
	m_fLog = fopen("c:\\packlog.txt", "a");
}


BlockBuilder::~BlockBuilder()
{
	if (m_code != NULL)
		VirtualFree(m_code, 0, MEM_RELEASE);
	if (m_fLog != NULL)
		fclose(m_fLog);

	CloseDisassembler(&m_dis);
}


bool BlockBuilder::BuildBlock(PBYTE startAddress, CONTEXT &ctx)
{
	INSTRUCTION *pIns;
	PBYTE ptr;
	DWORD dwFlags = DISASM_DECODE | DISASM_DISASSEMBLE;
	DWORD bbSize;
	
	m_codeSize = 0;

	ptr = startAddress;
	pIns = GetInstruction(&m_dis, (ULONG_PTR)ptr, ptr, dwFlags);
	while (pIns && !(pIns->Type == ITYPE_BRANCH ||
					pIns->Type == ITYPE_BRANCHCC ||
					pIns->Type == ITYPE_CALL ||
					pIns->Type == ITYPE_CALLCC ||
					pIns->Type == ITYPE_RET ||
					pIns->Type == ITYPE_LOOPCC))
	{
		m_codeSize += pIns->Length;
		ptr += pIns->Length;
		pIns = GetInstruction(&m_dis, (ULONG_PTR)ptr, ptr, dwFlags);
	}

	if (pIns == NULL && m_codeSize == 0) {
		// Disassembler could not disassemble first instruction
		MessageBox(NULL, "BB pIns == NULL", "INFO", MB_OK);
		return false;
	}

	// m_codeSize can be modified later.
	bbSize = m_codeSize;
	if (m_codeSize == 0) {

		// First instruction of a basic block
		// is CF changing instruction. The decision
		// must be made where the control will lead to.
		//char buff[20];
		//sprintf(buff, "%08X", pIns->CodeBranch.Operand->TargetAddress);
		//MessageBox(NULL, buff, "Addr", MB_OK);
		switch (pIns->Type) {
			case ITYPE_RET:
				{
					// Here we must change return address on the stack.
					
					PDWORD pRetAddress = (PDWORD)ctx.Esp;
					pRetAddress = (PDWORD)(*pRetAddress);
					//char buff[25];
					//sprintf(buff, "RET %08X", pRetAddress);
					//MessageBox(NULL, buff, "CRACH", MB_OK);

					DWORD shrinkStack = 4;

					if (pIns->OperandCount > 0) {
						WORD a = (WORD)(*(pIns->Address + 1));
						shrinkStack += a;
					//	char buff[20];
					//	sprintf(buff, "SHRINK %X %X", shrinkStack, a);
					//	MessageBox(NULL, buff, "aaa", MB_OK);
					}

					m_pNextInstruction = (PBYTE)pRetAddress;
/*
					if (pIns->OperandCount > 0) {
						char buff[20];
						sprintf(buff, "SHRINK %08X", m_pNextInstruction);
						MessageBox(NULL, buff, "aaa", MB_OK);
					}
*/
					// ADD esp, shrinkStack
					m_code[0] = 0x81;
					m_code[1] = 0xC4;
					*(PDWORD)(m_code + 2) = shrinkStack;

					m_codeSize = 6;

					//fprintf(m_fLog, "RET %08X\n", m_pNextInstruction);

				}
				break;
			case ITYPE_BRANCH:
				{
					// unconditional jump
					if (pIns->OpcodeBytes[0] == 0xFF) {
						m_pNextInstruction = (PBYTE)GetIndirectCallAddress(pIns->Address + 1, ctx);
						char buff[20];
						sprintf(buff, "%08X", m_pNextInstruction);
						MessageBox(NULL, buff, "", MB_OK);
						WriteLog();
					} else {
						m_pNextInstruction = (PBYTE)(pIns->CodeBranch.Addresses[0]);
					}
					//fprintf(m_fLog, "BRANCH %08X\n", m_pNextInstruction);
				}
				break;
			case ITYPE_BRANCHCC:
			case ITYPE_LOOPCC:
				
				if (IsContidionalBranchTaken(pIns->OpcodeBytes, ctx)) {
					m_pNextInstruction = (PBYTE)pIns->CodeBranch.Addresses[0];
					if (pIns->Type = ITYPE_LOOPCC) {
						// DEC ecx
						m_code[0] = 0x49;
						m_codeSize = 1;
					}
				} else {
					m_pNextInstruction = pIns->Address + pIns->Length;
				}

				//fprintf(m_fLog, "CC %08X\n", m_pNextInstruction);
				break;
			case ITYPE_CALL:
			case ITYPE_CALLCC:
				{
					// Save return address on the stack
					m_code[0] = 0x68;	// PUSH imm32
					*(PDWORD)(m_code + 1) = (DWORD)(pIns->Address + pIns->Length);
					m_codeSize += 5;

					if (pIns->OpcodeBytes[0] == 0xFF) {
						//fprintf(m_fLog, "START ADDRESS: %08X\n", startAddress);
						m_pNextInstruction = (PBYTE)GetIndirectCallAddress(pIns->Address + 1, ctx);
						//fprintf(m_fLog, "INDIRECT CALL %08X\n", m_pNextInstruction);
						//fflush(m_fLog);
					} else {
						PDWORD addr = (PDWORD)(pIns->Address + 1);
						if (*addr == 0)
							m_pNextInstruction = pIns->Address + pIns->Length;
						else
							m_pNextInstruction = (PBYTE)(pIns->CodeBranch.Addresses[0]);
					}
				}
				break;
		}
	} else {
		//fprintf(f, "NORMAL CASE case\n");
		m_pNextInstruction = pIns->Address;
		CopyMemory(m_code, startAddress, m_codeSize);
	}

	//if (m_pNextInstruction == (PBYTE)0x7c90ed0c)
	//	MessageBox(NULL, "Aattach", "aa", MB_OK);

	// Update basic block list
	std::vector<BASIC_BLOCK>::iterator it;
	it = FindBasicBlock((DWORD)startAddress);
	if (it != m_basicBlocks.end())
		it->executionCount++;
	else {
		BASIC_BLOCK bb;
		bb.executionCount = 1;
		bb.startAddress = (DWORD)startAddress;
		bb.checksum = 0;
		bb.size = bbSize;
		m_basicBlocks.push_back(bb);
	}
/*
	if (startAddress == (PBYTE)0x7c90d05e) {
		for (it = m_basicBlocks.begin(); it != m_basicBlocks.end(); it++)
			fprintf(m_fLog, "%08X %d %d\n", it->startAddress, it->executionCount, it->size);
		fflush(m_fLog);
	}
*/
	if (m_pNextInstruction == (PBYTE)FakeNtContinue)
		EmitJump((PBYTE)m_code + m_codeSize, (PBYTE)FakeNtContinue);
	else
		EmitJump((PBYTE)m_code + m_codeSize, (PBYTE)Dispatcher);

	return true;
}


PVOID BlockBuilder::GetBBAddress()
{
	return m_code;
}


DWORD BlockBuilder::GetCodeSize()
{
	return m_codeSize;
}

PBYTE BlockBuilder::GetNextInstructionAddress()
{
	return m_pNextInstruction;
}


std::vector<BASIC_BLOCK>::iterator BlockBuilder::FindBasicBlock(DWORD startAddress)
{
	std::vector<BASIC_BLOCK>::iterator it;

	for (it = m_basicBlocks.begin(); it != m_basicBlocks.end(); it++)
		if (it->startAddress == startAddress)
			return it;
	return it;
}


bool BlockBuilder::IsContidionalBranchTaken(BYTE opcode[2], CONTEXT ctx)
{
	bool sf, of, pf, zf, cf;

	sf = (ctx.EFlags & EFLAGS_SF) > 0;
	of = (ctx.EFlags & EFLAGS_OF) > 0;
	pf = (ctx.EFlags & EFLAGS_PF) > 0;
	zf = (ctx.EFlags & EFLAGS_ZF) > 0;
	cf = (ctx.EFlags & EFLAGS_CF) > 0;

	switch (opcode[0]) {
		case 0x77:
			// CF = 0 and ZF = 0
			if (!cf && !zf)
				return true;
			break;
		case 0x73:
			// CF = 0
			return !cf;
			break;
		case 0x72:
			// CF = 1
			return cf;
			break;
		case 0x76:
			// CF = 1 or ZF = 1
			if (cf || zf)
				return true;
			break;
		case 0xE3:
			// ECX = 0, CX = 0, RCX = 0
			if (ctx.Ecx == 0)
				return true;
			break;
		case 0x74:
			// ZF = 1
			return zf;
			break;
		case 0x7F:
			// ZF = 0 and SF = OF
			if (!zf && (sf == of))
				return true;
			break;
		case 0x7D:
			// SF = OF
			if (sf == of)
				return true;
			break;
		case 0x7C:
			// SF != OF
			if (sf != of)
				return true;
			break;
		case 0x7E:
			// ZF = 1 or SF != OF
			if (zf || (sf != of))
				return true;
			break;
		case 0x75:
			// ZF = 0
			return !zf;
			break;
		case 0x71:
			// OF = 0
			return !of;
			break;
		case 0x7B:
			// PF = 0
			return !pf;
			break;
		case 0x79:
			// SF = 0
			return !sf;
			break;
		case 0x70:
			// OF = 1
			return of;
			break;
		case 0x7A:
			// PF = 1
			return pf;
			break;
		case 0x78:
			// SF = 1
			return sf;
			break;
		case 0x0F:
			switch (opcode[1]) {
				case 0x87:
					// CF = 0 and ZF = 0
					if (!cf && !zf)
						return true;
					break;
				case 0x83:
					// CF = 0
					return !cf;
					break;
				case 0x82:
					// CF = 1
					return cf;
					break;
				case 0x86:
					// CF = 1 or ZF = 1
					if (cf || zf)
						return true;
					break;
				case 0x84:
					// ZF = 1
					return zf;
					break;
				case 0x8F:
					// ZF = 0 and SF = OF
					if (!zf && (sf == of))
						return true;
					break;
				case 0x8D:
					// SF = OF
					if (sf == of)
						return true;
					break;
				case 0x8C:
					// SF != OF
					if (sf != of)
						return true;
					break;
				case 0x8E:
					// ZF = 1 or SF != OF
					if (zf || (sf != of))
						return true;
					break;
				case 0x85:
					// ZF = 0
					return !zf;
					break;
				case 0x81:
					// OF = 0
					return !of;
					break;
				case 0x8B:
					// PF = 0
					return !pf;
					break;
				case 0x89:
					// SF = 0
					return !sf;
					break;
				case 0x80:
					// OF = 1
					return of;
					break;
				case 0x8A:
					// PF = 1
					return pf;
					break;
				case 0x88:
					// SF = 1
					return sf;
					break;
			}
			break;
		// LOOP/LOOPcc
		case 0xE2:
			if (ctx.Ecx != 0)
				return true;
			break;
		case 0XE1:
			if ((ctx.Ecx != 0) && zf)
				return true;
			break;
		case 0xE0:
			if ((ctx.Ecx != 0) && !zf)
				return true;
			break;
	}
	return false;
}


BYTE BlockBuilder::GetMod(BYTE modrm)
{
	return ((modrm >> 6) & 0x03);
}


BYTE BlockBuilder::GetRM(BYTE modrm)
{
	return (modrm & 0x07);
}


BYTE BlockBuilder::GetReg(BYTE modrm)
{
	return ((modrm >> 3) & 0x07);
}


BYTE BlockBuilder::GetScale(BYTE sib)
{
	return GetMod(sib);
}


BYTE BlockBuilder::GetIndex(BYTE sib)
{
	return GetReg(sib);
}


BYTE BlockBuilder::GetBase(BYTE sib)
{
	return GetRM(sib);
}


DWORD BlockBuilder::GetAddressFromSib(BYTE modrm, PBYTE sib, PCONTEXT ctx)
{
	DWORD address;
	DWORD regs[8];
	BYTE base, index, scale;

	regs[REG_EAX] = ctx->Eax;
	regs[REG_EBX] = ctx->Ebx;
	regs[REG_ECX] = ctx->Ecx;
	regs[REG_EDX] = ctx->Edx;
	regs[REG_EBP] = ctx->Ebp;
	regs[REG_ESP] = ctx->Esp;
	regs[REG_ESI] = ctx->Esi;
	regs[REG_EDI] = ctx->Edi;

	index = GetIndex(*sib);
	base = GetBase(*sib);
	scale = GetScale(*sib);

	if (base != 5)
		address = (regs[index] << scale) + regs[base];
	else {
		switch (GetMod(modrm)) {
			case 0:
				{
					/*char buff[30];
					sprintf(buff, "%d << %d + %08X", regs[index], scale, *(PDWORD)(sib + 1));
					MessageBox(NULL, buff, "aa", 0);*/
				}
				address = (regs[index] << scale) + *(PDWORD)(sib + 1);
				break;
			case 1:
				address = (regs[index] << scale) + *(sib + 1) + regs[REG_EBP];
				break;
			case 2:
				address = (regs[index] << scale) + *(PDWORD)(sib + 1) + regs[REG_EBP];
				break;
		}
	}

	return *(PDWORD)address;
}


DWORD BlockBuilder::GetIndirectCallAddress(PBYTE operands, CONTEXT ctx)
{
	switch (operands[0]) {
		#pragma region MOD00
		case 0x00:
		case 0x08:
		case 0x10:
		case 0x18:
		case 0x20:
		case 0x28:
		case 0x30:
		case 0x38:	// call [eax]
			return *(PDWORD)ctx.Eax;
			break;
		case 0x01:
		case 0x09:
		case 0x11:
		case 0x19:
		case 0x21:
		case 0x29:
		case 0x31:
		case 0x39:	// call [ecx]
			return *(PDWORD)ctx.Ecx;
			break;
		case 0x02:
		case 0x0A:
		case 0x12:
		case 0x1A:
		case 0x22:
		case 0x2A:
		case 0x32:
		case 0x3A:	// call [edx]
			return *(PDWORD)ctx.Edx;
			break;
		case 0x03:
		case 0x0B:
		case 0x13:
		case 0x1B:
		case 0x23:
		case 0x2B:
		case 0x33:
		case 0x3B:	// call [ebx]
			return *(PDWORD)ctx.Ebx;
			break;
		case 0x04:
		case 0x0C:
		case 0x14:
		case 0x1C:
		case 0x24:
		case 0x2C:
		case 0x34:
		case 0x3C:	// call [--][--]
			return GetAddressFromSib(operands[0], &operands[1], &ctx);
			break;
		case 0x05:
		case 0x0D:
		case 0x15:
		case 0x1D:
		case 0x25:
		case 0x2D:
		case 0x35:
		case 0x3D:	// disp32
			{
			PDWORD addr = (PDWORD)(operands + 1);
			addr = (PDWORD)(*addr);
			return *addr;
			}
			break;
		case 0x06:
		case 0x0E:
		case 0x16:
		case 0x1E:
		case 0x26:
		case 0x2E:
		case 0x36:
		case 0x3E:	// call [esi]
			return *(PDWORD)ctx.Esi;
			break;
		case 0x07:
		case 0x0F:
		case 0x17:
		case 0x1F:
		case 0x27:
		case 0x2F:
		case 0x37:
		case 0x3F:	// call [edi]
			return *(PDWORD)ctx.Edi;
			break;
		#pragma endregion MOD00
		#pragma region MOD01
		case 0x40:
		case 0x48:
		case 0x50:
		case 0x58:
		case 0x60:
		case 0x68:
		case 0x70:
		case 0x78:	// call [eax + sbyte]
			return *(PDWORD)(ctx.Eax + operands[1]);
			break;
		case 0x41:
		case 0x49:
		case 0x51:
		case 0x59:
		case 0x61:
		case 0x69:
		case 0x71:
		case 0x79:	// call [ecx + sbyte]
			return *(PDWORD)(ctx.Ecx + operands[1]);
			break;
		case 0x42:
		case 0x4A:
		case 0x52:
		case 0x5A:
		case 0x62:
		case 0x6A:
		case 0x72:
		case 0x7A:	// call [edx + sbyte]
			return *(PDWORD)(ctx.Edx + operands[1]);
			break;
		case 0x43:
		case 0x4B:
		case 0x53:
		case 0x5B:
		case 0x63:
		case 0x6B:
		case 0x73:
		case 0x7B:	// call [ebx + sbyte]
			return *(PDWORD)(ctx.Ebx + operands[1]);
			break;
		case 0x44:
		case 0x4C:
		case 0x54:
		case 0x5C:
		case 0x64:
		case 0x6C:
		case 0x74:
		case 0x7C:	// call [sib + sbyte]
			return GetAddressFromSib(operands[0], operands + 1, &ctx);
			break;
		case 0x45:
		case 0x4D:
		case 0x55:
		case 0x5D:
		case 0x65:
		case 0x6D:
		case 0x75:
		case 0x7D:	// call [ebp + sbyte]
			return *(PDWORD)(ctx.Ebp + operands[1]);
			break;
		case 0x46:
		case 0x4E:
		case 0x56:
		case 0x5E:
		case 0x66:
		case 0x6E:
		case 0x76:
		case 0x7E:	// call [esi + sbyte]
			return *(PDWORD)(ctx.Esi + operands[1]);
			break;
		case 0x47:
		case 0x4F:
		case 0x57:
		case 0x5F:
		case 0x67:
		case 0x6F:
		case 0x77:
		case 0x7F:	// call [edi + sbyte]
			return *(PDWORD)(ctx.Edi + operands[1]);
			break;
		#pragma endregion MOD01
		#pragma region MOD10
		case 0x80:
		case 0x88:
		case 0x90:
		case 0x98:
		case 0xA0:
		case 0xA8:
		case 0xB0:
		case 0xB8:	// call [eax + sdword]
			return *(PDWORD)(ctx.Eax + *(PDWORD)(&operands[1]));
			break;
		case 0x81:
		case 0x89:
		case 0x91:
		case 0x99:
		case 0xA1:
		case 0xA9:
		case 0xB1:
		case 0xB9:	// call [ecx + sdword]
			return *(PDWORD)(ctx.Ecx + *(PDWORD)(&operands[1]));
			break;
		case 0x82:
		case 0x8A:
		case 0x92:
		case 0x9A:
		case 0xA2:
		case 0xAA:
		case 0xB2:
		case 0xBA:	// call [edx + sdword]
			return *(PDWORD)(ctx.Edx + *(PDWORD)(&operands[1]));
			break;
		case 0x83:
		case 0x8B:
		case 0x93:
		case 0x9B:
		case 0xA3:
		case 0xAB:
		case 0xB3:
		case 0xBB:	// call [ebx + sdword]
			return *(PDWORD)(ctx.Ebx + *(PDWORD)(&operands[1]));
			break;
		case 0x84:
		case 0x8C:
		case 0x94:
		case 0x9C:
		case 0xA4:
		case 0xAC:
		case 0xB4:
		case 0xBC:	// call [sib + sdword]
			return GetAddressFromSib(operands[0], &operands[1], &ctx);
			break;
		case 0x85:
		case 0x8D:
		case 0x95:
		case 0x9D:
		case 0xA5:
		case 0xAD:
		case 0xB5:
		case 0xBD:	// call [ebp + sdword]
			return *(PDWORD)(ctx.Ebp + *(PDWORD)(&operands[1]));
			break;
		case 0x86:
		case 0x8E:
		case 0x96:
		case 0x9E:
		case 0xA6:
		case 0xAE:
		case 0xB6:
		case 0xBE:	// call [esi + sdword]
			return *(PDWORD)(ctx.Esi + *(PDWORD)(&operands[1]));
			break;
		case 0x87:
		case 0x8F:
		case 0x97:
		case 0x9F:
		case 0xA7:
		case 0xAF:
		case 0xB7:
		case 0xBF:	// call [edi + sdword]
			return *(PDWORD)(ctx.Edi + *(PDWORD)(&operands[1]));
			break;
		#pragma endregion MOD10
		#pragma region MOD11
		// incomplete
		case 0xD0:
			return ctx.Eax;
			break;
		case 0xD1:
			return ctx.Ecx;
			break;
		case 0xD2:
			return ctx.Edx;
			break;
		case 0xD3:
			return ctx.Ebx;
			break;
		case 0xD4:
			return ctx.Esp;
			break;
		case 0xD5:
			return ctx.Ebp;
			break;
		case 0xD6:
			return ctx.Esi;
			break;
		case 0xD7:
			return ctx.Edi;
			break;
		#pragma endregion MOD11
	}
	return 0;
}