#include <winternl.h>
#if defined(_WIN64)
	#include <intrin.h>
#endif

class PatchHook
{
private:
	BYTE* m_OriginalBytes{};
	DWORD m_Address, m_FunctionHookAddress, m_Size;
	void* m_FunctionBackup;
	bool m_GenerateBackup;
	void FixRelatives(DWORD Address, DWORD Size) const;

public:
	PatchHook(DWORD Address, DWORD FunctionHookAddress, DWORD Size, bool GenerateBackupFunction = false);
	bool ApplyHook();
	bool RemoveHook() const;
	bool Hooked() const;
	void* GetBackupFunction() const;
	~PatchHook();
};
