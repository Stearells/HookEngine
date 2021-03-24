#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <TlHelp32.h>
#include <string>

namespace HookEngine
{
#ifdef _WIN64
	typedef uint64_t uint_auto;
#else
	typedef uint32_t uint_auto;
#endif

	class Hook
	{
	private:
		unsigned char* pOldCode;
		uint_auto*     pAddress;

	public:
		Hook();
		~Hook();

		bool        Install(void* pFunction, void* pHook);
		uint_auto*  Uninstall();
		bool        IsInstalled();
	};

	uint_auto       FindFunction(LPCWSTR moduleName, LPCSTR functionName);
	DWORD           GetProcessIDByName(const std::wstring& processName);
	bool            IsWoW64Process(int processID);
}