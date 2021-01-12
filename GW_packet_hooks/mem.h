#pragma once
#include <Windows.h>
DWORD Get_Base_Module(const wchar_t* name);
BYTE* TrampHook32(BYTE* src, BYTE* dst, const uintptr_t len);
bool Detour32(BYTE* src, BYTE* dst, const uintptr_t len);