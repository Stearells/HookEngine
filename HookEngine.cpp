﻿#include "HookEngine.h"

HookEngine::Hook::Hook()
{
	pAddress = nullptr;
	pOldCode = nullptr;
}

HookEngine::Hook::~Hook()
{
	if (pOldCode)
		Uninstall();
}

bool HookEngine::Hook::Install(void* pFunction, void* pHook)
{
	if (pOldCode)
		return false;

	if (!pFunction || !pHook)
		return false; 
	
#ifdef _WIN64
	unsigned char newCode[] =
	{
		0x48, 0xB8,										  // mov rax
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	  // pHook
		0x50,											  // push rax (return address)
		0xC3											  // ret
	};

	*((uint_auto*)&newCode[2]) = (uint_auto)pHook;
#else
	unsigned char newCode[] =
	{
		0xB8,											  // mov eax
		0x00, 0x00, 0x00, 0x00,							  // pHook
		0x50,											  // push eax (return address)
		0xC3											  // ret
	};

	*((uint_auto*)&newCode[1]) = (uint_auto)pHook;
#endif

	pOldCode = new unsigned char[sizeof(newCode)];
	if (!pOldCode)
		return false;

	DWORD dwBack;
	VirtualProtect(pFunction, sizeof(newCode), PAGE_EXECUTE_READWRITE, &dwBack);

	std::memcpy(pOldCode, pFunction, sizeof(newCode));
	std::memcpy(pFunction, &newCode, sizeof(newCode));

	pAddress = (uint_auto*)pFunction;
	return true;
}

HookEngine::uint_auto* HookEngine::Hook::Uninstall()
{
	if (!pOldCode)
		return nullptr;

	std::memcpy(pAddress, pOldCode, sizeof(pOldCode));
	delete[] pOldCode;
	pOldCode = nullptr;

	return pAddress;
}

bool HookEngine::Hook::IsInstalled()
{
	return pOldCode ? true : false;
}

HookEngine::uint_auto HookEngine::FindFunction(LPCWSTR moduleName, LPCSTR functionName)
{
	HMODULE hMod = GetModuleHandle(moduleName);
	if (!hMod)
		hMod = LoadLibrary(moduleName);

	if (!hMod)
		return 0;

	return (uint_auto)GetProcAddress(hMod, functionName);
}

DWORD HookEngine::GetProcessIDByName(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

bool HookEngine::IsWoW64Process(int processID)
{
	BOOL result;
	IsWow64Process((HANDLE)processID, &result);
	return result;
}