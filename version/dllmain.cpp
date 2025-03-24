#include <Windows.h>
#include <string>
#include "version.h"
#include "detours.h"
#pragma comment(lib, "detours.lib")

// steam="yes"
const BYTE* SEARCHED = (const BYTE*)"\x73\x74\x65\x61\x6D\x3D\x22\x79\x65\x73\x22";
// steam="no"\x0A
const BYTE* EDITED = (const BYTE*)"\x73\x74\x65\x61\x6D\x3D\x22\x6E\x6F\x22\x0A";

const int SEARCHED_SIZE = 11;

static bool IsTargetFound = false;
static int ResSize = 0;
static bool IsPatternFound = false;
static bool IsReplaced = false;

typedef HRSRC(WINAPI* FindResourceW_t)(HMODULE, LPCWSTR, LPCWSTR);
typedef DWORD(WINAPI* SizeOfResource_t)(HMODULE, HRSRC);
typedef HGLOBAL(WINAPI* LoadResource_t)(HMODULE, HRSRC);
FindResourceW_t Real_FindResourceW = FindResourceW;
SizeOfResource_t Real_SizeOfResource = SizeofResource;
LoadResource_t Real_LoadResource = LoadResource;

HRSRC WINAPI Hook_FindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType)
{
	if (!IsTargetFound && !IsReplaced)
	{
		if (Real_FindResourceW == NULL)
		{
			MessageBoxW(NULL, L"Real_FindResourceW is NULL", L"Error", MB_OK);
			return NULL;
		}

		//MessageBoxA(NULL, "Searching for target", "version", MB_OK);
		if (wcscmp(lpType, L"TEXT") == 0 && IS_INTRESOURCE(lpName) && (reinterpret_cast<USHORT>(lpName) == 139))
		{
			IsTargetFound = true;
			//MessageBoxA(NULL, "Target found", "version", MB_OK);
		}
	}

	return Real_FindResourceW(hModule, lpName, lpType);
}

DWORD WINAPI Hook_SizeOfResource(HMODULE hModule, HRSRC hResInfo)
{
	if (IsTargetFound && !IsReplaced)
	{
		if (Real_SizeOfResource == NULL)
		{
			MessageBoxW(NULL, L"Real_SizeOfResource is NULL", L"Error", MB_OK);
			return 0;
		}
		if (IsTargetFound)
		{
			ResSize = Real_SizeOfResource(hModule, hResInfo);
		}
	}
	return Real_SizeOfResource(hModule, hResInfo);
}

HGLOBAL WINAPI Hook_LoadResource(HMODULE hModule, HRSRC hResInfo)
{
	if (Real_LoadResource == NULL)
	{
		MessageBoxW(NULL, L"Real_LoadResource is NULL", L"Error", MB_OK);
		return NULL;
	}
	if (IsTargetFound && !IsPatternFound && !IsReplaced)
	{
		HGLOBAL hGlobal = Real_LoadResource(hModule, hResInfo);
		if (hGlobal != NULL)
		{
			void* pData = LockResource(hGlobal);
			if (pData != NULL && ResSize > 0)
			{
				// Search and replace pattern
				for (int i = 0; i < ResSize - SEARCHED_SIZE; ++i)
				{
					if (memcmp((const BYTE*)pData + i, SEARCHED, SEARCHED_SIZE) == 0)
					{
						IsPatternFound = true;
						//MessageBoxA(NULL, "Pattern found. Replacing...", "version", MB_OK);
						DWORD oldProtect;
						VirtualProtect(pData, ResSize, PAGE_EXECUTE_READWRITE, &oldProtect);
						memcpy((BYTE*)pData + i, EDITED, SEARCHED_SIZE);
						VirtualProtect(pData, ResSize, oldProtect, &oldProtect);
						//MessageBoxA(NULL, "Pattern replaced.", "version", MB_OK);
						IsReplaced = true;
						break;
					}
				}
			}
			UnlockResource(hGlobal);
			return hGlobal;
		}
	}
	return Real_LoadResource(hModule, hResInfo);
}

void InstallHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)Real_FindResourceW, Hook_FindResourceW);
	DetourAttach(&(PVOID&)Real_SizeOfResource, Hook_SizeOfResource);
	DetourAttach(&(PVOID&)Real_LoadResource, Hook_LoadResource);
	if (DetourTransactionCommit() != NO_ERROR)
	{
		MessageBoxA(NULL, "Failed to install hooks", "version", MB_OK);
	}
}

void FreeHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)Real_FindResourceW, Hook_FindResourceW);
	DetourDetach(&(PVOID&)Real_SizeOfResource, Hook_SizeOfResource);
	DetourDetach(&(PVOID&)Real_LoadResource, Hook_LoadResource);
	if (DetourTransactionCommit() != NO_ERROR)
	{
		MessageBoxA(NULL, "Failed to free hooks", "version", MB_OK);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			InstallHooks();
			Init();
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			FreeHooks();
			Free();
			break;
	}
	return TRUE;
}