#include "pch.h"
#include "mem.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

DWORD Get_Base_Module(const wchar_t * name) {
	// define variables
	DWORD baseaddress = 0;
	DWORD current_process = GetCurrentProcessId();
	HANDLE mhandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, current_process);

	MODULEENTRY32W mentry;
	mentry.dwSize = sizeof(MODULEENTRY32W);


		if (Module32FirstW(mhandle, &mentry)) {
			do {
				if (!_wcsicmp(name, mentry.szModule)) {
					baseaddress = (DWORD)mentry.modBaseAddr;
					break;
				}
			} while (Module32NextW(mhandle, &mentry));
		}



	return baseaddress;
}

bool Detour32(BYTE* src, BYTE* dst, const uintptr_t len) {

	if (len < 5)  return false;

	DWORD current_protection;
	VirtualProtect(src, 7, PAGE_EXECUTE_READWRITE, &current_protection);
	uintptr_t relative_address = dst - src - 7; // always set to 5 because we want to manage jump opcode
	//pushfd
	*src = 0x60;
	//pushfd
	*(src + 1) = 0x9c;
	//set jump
	*(src + 2) = 0xE9; // jmp
	//plus 3 at relative address src + 3
	*(uintptr_t *)(src + 3) = relative_address;
	VirtualProtect(src, 7, current_protection, &current_protection);

	return true;

}

// src is where you want to hijack
// dst is where place you want to trampoline
// len is amount of byte want to copy
BYTE* TrampHook32(BYTE* src, BYTE* dst, const uintptr_t len) {

	//Create Gateway
	BYTE* gateway = (BYTE *)VirtualAlloc(0, 20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//popad
	*gateway = 0x61;
	//popfd
	*(gateway+1) = 0x9d;
	//copy amount of opcode to gateway.
	memcpy_s((gateway+2),len,src,len);

	//calculate the distance from source to gateway. , minus len is to adjust after we put opcode on gateway
	uintptr_t gateway_relative_address = src - gateway - 14;

	// add the jump opcode to the end of the gateway.
	*(gateway + len + 2) = 0xE9;

	//Write the address of the gateway to the jump
	*(uintptr_t*)((uintptr_t)gateway + len + 3) = gateway_relative_address;

	//Performed the detour
	Detour32(src,dst,len);

	return gateway;
}