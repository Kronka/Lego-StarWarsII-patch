#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <windows.h>
#include <stdint.h>

#include <cstdint>
#include <random>
#include <string>

#include <chrono>
#include <thread>

#include <time.h> 

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <float.h>
#include <shellapi.h>
#include <assert.h>
#include <algorithm>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <functional>

#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>
#include <string.h>

#include <d3dx9.h>
#include "MinHook.h"
#pragma comment(lib, "libMinHook.x86.lib")

void Log(const char* fmt, ...);

HINSTANCE g_hOrigDll = NULL;

// Orig exception filter
LPTOP_LEVEL_EXCEPTION_FILTER OrigExceptionFilter;

FILE* g_flLog = NULL;

HMODULE g_hDllModule = 0;

LONG WINAPI unhandledExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	Log(" ---------------------------------------------------------------------");
	Log(" Lego Star Wars II has crashed.");
	Log(" Base address: 0x%p", g_hDllModule);
	Log(" Exception at address: 0x%p", ExceptionInfo->ExceptionRecord->ExceptionAddress);

	int m_ExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
	int m_exceptionInfo_0 = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
	int m_exceptionInfo_1 = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
	int m_exceptionInfo_2 = ExceptionInfo->ExceptionRecord->ExceptionInformation[2];
	switch (m_ExceptionCode)
	{
	case EXCEPTION_ACCESS_VIOLATION:
		Log(" Cause: EXCEPTION_ACCESS_VIOLATION");
		if (m_exceptionInfo_0 == 0)
		{
			// bad read
			Log(" Attempted to read from: 0x%08x", m_exceptionInfo_1);
		}
		else if (m_exceptionInfo_0 == 1)
		{
			// bad write
			Log(" Attempted to write to: 0x%08x", m_exceptionInfo_1);
		}
		else if (m_exceptionInfo_0 == 8)
		{
			// user-mode data execution prevention (DEP)
			Log(" Data Execution Prevention (DEP) at: 0x%08x", m_exceptionInfo_1);
		}
		else
		{
			// unknown, shouldn't happen
			Log(" Unknown access violation at: 0x%08x", m_exceptionInfo_1);
		}
		break;

	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		Log(" Cause: EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
		break;

	case EXCEPTION_BREAKPOINT:
		Log(" Cause: EXCEPTION_BREAKPOINT");
		break;

	case EXCEPTION_DATATYPE_MISALIGNMENT:
		Log(" Cause: EXCEPTION_DATATYPE_MISALIGNMENT");
		break;

	case EXCEPTION_FLT_DENORMAL_OPERAND:
		Log(" Cause: EXCEPTION_FLT_DENORMAL_OPERAND");
		break;

	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		Log(" Cause: EXCEPTION_FLT_DIVIDE_BY_ZERO");
		break;

	case EXCEPTION_FLT_INEXACT_RESULT:
		Log(" Cause: EXCEPTION_FLT_INEXACT_RESULT");
		break;

	case EXCEPTION_FLT_INVALID_OPERATION:
		Log(" Cause: EXCEPTION_FLT_INVALID_OPERATION");
		break;

	case EXCEPTION_FLT_OVERFLOW:
		Log(" Cause: EXCEPTION_FLT_OVERFLOW");
		break;

	case EXCEPTION_FLT_STACK_CHECK:
		Log(" Cause: EXCEPTION_FLT_STACK_CHECK");
		break;

	case EXCEPTION_FLT_UNDERFLOW:
		Log(" Cause: EXCEPTION_FLT_UNDERFLOW");
		break;

	case EXCEPTION_ILLEGAL_INSTRUCTION:
		Log(" Cause: EXCEPTION_ILLEGAL_INSTRUCTION");
		break;

	case EXCEPTION_IN_PAGE_ERROR:
		Log(" Cause: EXCEPTION_IN_PAGE_ERROR");
		if (m_exceptionInfo_0 == 0)
		{
			// bad read
			Log(" Attempted to read from: 0x%08x", m_exceptionInfo_1);
		}
		else if (m_exceptionInfo_0 == 1)
		{
			// bad write
			Log(" Attempted to write to: 0x%08x", m_exceptionInfo_1);
		}
		else if (m_exceptionInfo_0 == 8)
		{
			// user-mode data execution prevention (DEP)
			Log(" Data Execution Prevention (DEP) at: 0x%08x", m_exceptionInfo_1);
		}
		else
		{
			// unknown, shouldn't happen
			Log(" Unknown access violation at: 0x%08x", m_exceptionInfo_1);
		}

		// log NTSTATUS
		Log(" NTSTATUS: 0x%08x", m_exceptionInfo_2);
		break;

	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		Log(" Cause: EXCEPTION_INT_DIVIDE_BY_ZERO");
		break;

	case EXCEPTION_INT_OVERFLOW:
		Log(" Cause: EXCEPTION_INT_OVERFLOW");
		break;

	case EXCEPTION_INVALID_DISPOSITION:
		Log(" Cause: EXCEPTION_INVALID_DISPOSITION");
		break;

	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		Log(" Cause: EXCEPTION_NONCONTINUABLE_EXCEPTION");
		break;

	case EXCEPTION_PRIV_INSTRUCTION:
		Log(" Cause: EXCEPTION_PRIV_INSTRUCTION");
		break;

	case EXCEPTION_SINGLE_STEP:
		Log(" Cause: EXCEPTION_SINGLE_STEP");
		break;

	case EXCEPTION_STACK_OVERFLOW:
		Log(" Cause: EXCEPTION_STACK_OVERFLOW");
		break;

	case DBG_CONTROL_C:
		Log(" Cause: DBG_CONTROL_C (WTF!)");
		break;

	default:
		Log(" Cause: %08x", m_ExceptionCode);
	}

	Log(" EAX: 0x%08x || ESI: 0x%08x", ExceptionInfo->ContextRecord->Eax, ExceptionInfo->ContextRecord->Esi);
	Log(" EBX: 0x%08x || EDI: 0x%08x", ExceptionInfo->ContextRecord->Ebx, ExceptionInfo->ContextRecord->Edi);
	Log(" ECX: 0x%08x || EBP: 0x%08x", ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Ebp);
	Log(" EDX: 0x%08x || ESP: 0x%08x", ExceptionInfo->ContextRecord->Edx, ExceptionInfo->ContextRecord->Esp);

	Log(" ---------------------------------------------------------------------");

	STARTUPINFO cif;
	ZeroMemory(&cif, sizeof(STARTUPINFO));
	PROCESS_INFORMATION pi;

	if (OrigExceptionFilter)
		return OrigExceptionFilter(ExceptionInfo);

	return EXCEPTION_CONTINUE_SEARCH;
}

IDirect3D9* origIDirect3D9;
typedef IDirect3D9* (WINAPI* D3DC9) (UINT);
D3DC9	orig_Direct3DCreate9 = NULL;

bool dll_init()
{
	char	filename[MAX_PATH];
	GetSystemDirectory(filename, (UINT)(MAX_PATH - strlen("\\d3d9.dll") - 1));
	sprintf(filename, "%s\\d3d9.dll",filename);
	g_hOrigDll = LoadLibrary(filename);
	if (g_hOrigDll == NULL)
	{
		Log("Failed to load %s", filename);
		return false;
	}
	orig_Direct3DCreate9 = (D3DC9)GetProcAddress(g_hOrigDll, "Direct3DCreate9");
	if (orig_Direct3DCreate9 == NULL)
	{
		Log("%s does not export Direct3DCreate9!?", filename);
		FreeLibrary(g_hOrigDll);
		return false;
	}
	return true;
}

int (*o_sub_10986150)(DWORD* a1, DWORD* a2);
int hk_sub_10986150(DWORD* a1, DWORD* a2)
{
	Log("sub_10986150 loaded hook");
	if (!*(DWORD*)(*a2 + 4))
	{
		Log("dont exist!!!");
		exit(0);
	}
	else Log("is exist");
	return o_sub_10986150(a1,a2);
}

IDirect3D9* WINAPI sys_Direct3DCreate9(UINT SDKVersion)
{
	if (!dll_init())
	{
		Log("Game not started!");
		exit(0);
	}

	Log("Game is started!");
	
	Log("kernel32 = 0x%X", GetModuleHandleA("Kernel32"));
	Log("shell32 = 0x%X", GetModuleHandleA("shell32"));
	Log("user32 = 0x%X", GetModuleHandleA("user32"));
	Log("winmm = 0x%X", GetModuleHandleA("winmm"));
	Log("binkw32 = 0x%X", GetModuleHandleA("binkw32"));
	Log("d3dx9_30 = 0x%X", GetModuleHandleA("d3dx9_30"));
	//Log("nvd3dum = 0x%X", GetModuleHandleA("nvd3dum"));
	// try find nvd3dum
	//uint32_t test = (uint32_t)LoadLibrary("C:\\Windows\\System32\\DriverStore\\FileRepository\\nv_dispi.inf_amd64_c0e159863e7afdde\\nvd3dum.dll");
	//Log("nvd3dum = 0x%X",test);
	// try fix this problem
	//MH_CreateHook((void*)(test + 0x986150), &hk_sub_10986150, (void**)(&o_sub_10986150));
	//MH_EnableHook((void*)(test + 0x986150));

	return orig_Direct3DCreate9(SDKVersion);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		g_hDllModule = hModule;
		OrigExceptionFilter = SetUnhandledExceptionFilter(unhandledExceptionFilter);
		break;

	case DLL_PROCESS_DETACH:
		break;
	}

	return true;
}

void Log(const char* fmt, ...)
{
	SYSTEMTIME	time;
	va_list		ap;

	if (g_flLog == NULL)
	{
		char	filename[512];
		snprintf(filename, sizeof(filename), "starwars.log");

		g_flLog = fopen(filename, "w");
		if (g_flLog == NULL)
			return;
	}

	GetLocalTime(&time);
	fprintf(g_flLog, "[%02d:%02d:%02d.%03d] ", time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
	va_start(ap, fmt);
	vfprintf(g_flLog, fmt, ap);
	va_end(ap);
	fprintf(g_flLog, "\n");
	fflush(g_flLog);
}
