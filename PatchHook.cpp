#include "PatchHook.hpp"
#include <windows.h> //replace with pch.h if possible

void PatchHook::FixRelatives(DWORD Address, DWORD Size) const
{
	for (DWORD offset = 0; offset < Size; ++offset)
	{
		if (*reinterpret_cast<BYTE*>(Address + offset) == 0x0F)
		{
			const DWORD CorrectCalledFunctionAddress = (this->m_Address + offset) + *reinterpret_cast<DWORD*>(this->m_Address + offset + 2) + 6;
			const DWORD FixedCalledOffset = CorrectCalledFunctionAddress - (Address + offset) - 6;
			*reinterpret_cast<DWORD*>(Address + offset + 2) = FixedCalledOffset;
		}

		if (*reinterpret_cast<BYTE*>(Address + offset) == 0xE8 || *reinterpret_cast<BYTE*>(Address + offset) == 0xE9)
		{
			const DWORD CorrectCalledFunctionAddress = (this->m_Address + offset) + *reinterpret_cast<DWORD*>(this->m_Address + offset + 1) + 5;
			const DWORD FixedCalledOffset = CorrectCalledFunctionAddress - (Address + offset) - 5;
			*reinterpret_cast<DWORD*>(Address + offset + 1) = FixedCalledOffset;
		}
	}
}

PatchHook::PatchHook(DWORD Address, DWORD FunctionHookAddress, DWORD Size, bool GenerateBackupFunction): m_Address(Address), m_FunctionHookAddress(FunctionHookAddress),
                                                                     m_Size(Size), m_GenerateBackup(GenerateBackupFunction)
{
	this->m_OriginalBytes = new BYTE[this->m_Size];
	this->m_FunctionBackup = nullptr;
}



bool PatchHook::ApplyHook()
{
	DWORD oldProtection = 0;
	bool success = VirtualProtect(reinterpret_cast<void*>(this->m_Address), 1, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (success)
	{
		if (this->m_GenerateBackup)
		{
			DWORD allocationSize = 0x500;
			this->m_FunctionBackup = VirtualAlloc(NULL, allocationSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (this->m_FunctionBackup)
			{
				PPEB pEnvironmentBlock = { 0 };

				#if defined(_WIN64)
					pEnvironmentBlock = (PPEB)__readgsqword(0x60);
				#else
					__asm
					{
						push eax
						mov eax, fs: [30h]
						mov pEnvironmentBlock, eax
						pop eax
					}
				#endif

				if (pEnvironmentBlock)
				{
					PLIST_ENTRY currentEntry = pEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink;
					PLDR_DATA_TABLE_ENTRY currentTable = nullptr;
					
					while (currentEntry != &pEnvironmentBlock->Ldr->InMemoryOrderModuleList)
					{
						currentTable = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
						DWORD SizeOfImage = reinterpret_cast<DWORD>(currentTable->Reserved3[1]);

						if (this->m_Address > reinterpret_cast<DWORD>(currentTable->DllBase) &&
							this->m_Address < reinterpret_cast<DWORD>(currentTable->DllBase) + SizeOfImage)
						{
							if (reinterpret_cast<DWORD>(currentTable->DllBase) + SizeOfImage - this->m_Address < allocationSize)
							{
								allocationSize = reinterpret_cast<DWORD>(currentTable->DllBase) + SizeOfImage - this->m_Address;
							}
						}

						currentEntry = currentEntry->Flink;
					}
				}

				memcpy(this->m_FunctionBackup, reinterpret_cast<void* const>(this->m_Address), allocationSize);
				this->FixRelatives(reinterpret_cast<DWORD>(this->m_FunctionBackup), allocationSize);
			}
				
		}

		memcpy(this->m_OriginalBytes, reinterpret_cast<void* const>(this->m_Address), this->m_Size);
		*reinterpret_cast<BYTE*>(this->m_Address) = 0xE9;
		*reinterpret_cast<DWORD*>(this->m_Address + 1) = this->m_FunctionHookAddress - this->m_Address - 5;

		for (DWORD offset = 5; offset < this->m_Size; ++offset)
			*reinterpret_cast<BYTE*>(this->m_Address + offset) = 0x90;

		success = VirtualProtect(reinterpret_cast<void*>(this->m_Address), 1, oldProtection, &oldProtection);
	}

	return success;
}

bool PatchHook::RemoveHook() const
{
	DWORD oldProtection = 0;
	bool success = VirtualProtect(reinterpret_cast<void*>(this->m_Address), 1, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (success)
	{
		memcpy(reinterpret_cast<void*>(this->m_Address), this->m_OriginalBytes, this->m_Size);
		success = VirtualProtect(reinterpret_cast<void*>(this->m_Address), 1, oldProtection, &oldProtection);
	}

	return success;
}

bool PatchHook::Hooked() const
{
	DWORD oldProtection = 0;
	bool IsHooked = false;

	VirtualProtect(reinterpret_cast<void*>(this->m_Address), 1, PAGE_EXECUTE_READWRITE, &oldProtection);
	IsHooked = memcmp(reinterpret_cast<void*>(this->m_Address), "\xE9", 1) == 0;
	VirtualProtect(reinterpret_cast<void*>(this->m_Address), 1, oldProtection, &oldProtection);

	return IsHooked;
}

void* PatchHook::GetBackupFunction() const
{
	return this->m_GenerateBackup ? this->m_FunctionBackup : nullptr;
}

PatchHook::~PatchHook()
{
	if (this->Hooked())
		(void)this->RemoveHook();

	delete this->m_OriginalBytes;

	if (this->m_GenerateBackup)
		VirtualFree(this->m_FunctionBackup, NULL, MEM_RELEASE);
}

