/*
   _____ __                       ____
  / ___// /____  ____ _________  / / /____
  \__ \/ __/ _ \/ __ `/ ___/ _ \/ / / ___/
 ___/ / /_/  __/ /_/ / /  /  __/ / (__  )
/____/\__/\___/\__,_/_/   \___/_/_/____/
HookEngine Library
Stearells (C) 2021
*/


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
	typedef int64_t int_auto;
#else
	typedef uint32_t uint_auto;
	typedef int32_t int_auto;
#endif

	class CHook
	{
	private:
		unsigned char* pOldCode;
		uint_auto*     pAddress;

	public:
		CHook();
		~CHook();

		bool        Install(void* pFunction, void* pHook);
		uint_auto*  Uninstall();
		bool        IsInstalled();
	};

	uint_auto       FindFunction(LPCWSTR moduleName, LPCSTR functionName);
	DWORD           GetProcessIDByName(const std::wstring& processName);
	bool            IsWoW64Process(int processID);
	uint_auto*      FindMemoryPattern(void* pMemory, unsigned const char Pattern[], size_t MemorySize, size_t PatternSize, int Count);
}