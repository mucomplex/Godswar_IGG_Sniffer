// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "mem.h"

typedef void(*gateway)();

gateway fp;
VOID trampoline_func() {
	std::cout << "Trampoline!" << std::endl;
	DWORD content;
	int content_size;
	int holder;

	__asm {
		mov content_size, esi;
		mov content, edi;
	
	}
	

	std::cout << "Packet size " << std::hex << content_size << std::endl;
	
	for (int i = 0; i!= content_size; i++) {
		holder = ((BYTE*)content)[i];
		std::cout << std::hex << holder;
	}
	std::cout << '\n' << std::endl;

	for (int i = 0; i!= content_size; i++) {
		holder = ((BYTE*)content)[i];
		std::cout << "0x" << std::hex << holder <<",";
	}
	std::cout << '\n' << std::endl;
	for (int i = 0; i!= content_size; i++) {
		std::cout << ((BYTE*)content)[i];
	}
	std::cout << '\n' << std::endl;

	__asm {
		//remove calling trampoline
		pop eax;
		pop eax;
		pop eax;
		pop eax;
		pop eax;
		pop eax;
		//re allign the code
		popfd;
		popad;
	}

	__asm {
		POP EDI;
		POP EBP;
		POP EBX;
		POP ESI;
		retn 8;
	}
}

DWORD WINAPI packet_thread(HMODULE hModule) {
	AllocConsole();
	FILE* f;
	freopen_s(&f, "CONOUT$", "w", stdout);
	std::cout << "Client hooked!" << std::endl;
	//Get baseaddress
	DWORD * baseaddress = (DWORD *)Get_Base_Module(L"Net.dll");
	std::cout << std::hex << baseaddress << std::endl;
	fp = (gateway)TrampHook32((((BYTE*)baseaddress) + 0x656B),(BYTE *)trampoline_func,7);
	while (true) {
	
	}
	fclose(f);
	FreeConsole();
	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH: {
		CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)packet_thread, hModule, 0, nullptr));
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

