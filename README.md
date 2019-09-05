# PatchHookAPI
A short class to implement some basic patching, restoration, and function copying for backup.

## Supports
- x64 and x86 Hooks.
- Hook patching
- Hook unpatching (byte restoration)
- Function copying for backup

## Example Usage
```cpp
#include "PatchHook.hpp"

typedef int(WINAPI* tMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
tMessageBoxA MessageBoxABackup = nullptr;


int WINAPI MessageBoxAReplacement(HWND hWnd, LPCSTR text, LPCSTR caption, UINT type)
{
	if (strcmp(text, "This is Text") == 0) 
	{
		text = "Creative Text";
	}


	if (MessageBoxABackup)
		return MessageBoxABackup(hWnd, text, caption, type);
}

int main()
{

	PatchHook* MessageBoxHook = new PatchHook(reinterpret_cast<DWORD>(MessageBoxA), 
		reinterpret_cast<DWORD>(MessageBoxAReplacement), 5, true);

	if (MessageBoxHook->ApplyHook())
	{
		MessageBoxABackup = reinterpret_cast<tMessageBoxA>(MessageBoxHook->GetBackupFunction());
	}

	MessageBoxA(0, "This is Text", "Creative Caption", MB_OK);
}
```
