#define _CRT_SECURE_NO_WARNINGS

#include<Windows.h>
#include<tchar.h>
#include<iostream>
#include<stdint.h>
#include<chrono>
#include<thread>
#include <TlHelp32.h>
#include<Psapi.h>
#include<string>

typedef int8_t u8; //1byte
typedef int16_t u16;
typedef int32_t u32;
typedef int64_t u64; //8byte

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	char windowTitle[256];
	GetWindowTextA(hWnd, windowTitle, 256);
	TCHAR windowTitle_t[256];
	if (!strncmp(windowTitle, "Citra Nightly", strlen("Citra Nightly"))) {
		std::cout << "got window name " << windowTitle << std::endl;
		strcpy(reinterpret_cast<char*>(lParam), windowTitle);
		return FALSE;
	}
	return TRUE;
}

u8* GetBasePointer(HANDLE citra_process) {
	/*
	TCHAR main_exe_name[512];
	GetProcessImageFileName(citra_process, main_exe_name, 256);
	std::cout << "Got main module named ";
	std::wcout << main_exe_name << std::endl;
	*/

	HMODULE hmodules[1024];
	DWORD cbNeeded;

	unsigned int i = 0;

	if (EnumProcessModules(citra_process, hmodules, sizeof(hmodules), &cbNeeded)) {
		
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			TCHAR module_name[512];
			if (GetModuleFileNameEx(citra_process, hmodules[i], module_name, sizeof(module_name))) {
				std::wstring wmain_name = L"citra-qt.exe";
				std::wstring wmodule_name = module_name;

				if (wmodule_name.find(wmain_name) != std::string::npos) {
					std::wcout << wmodule_name << std::endl;
					break;
				}
			}
			
		}
	}

	MODULEINFO module_info;
	GetModuleInformation(citra_process, hmodules[i], &module_info, sizeof(MODULEINFO));

	return (u8*)module_info.lpBaseOfDll;
}

int get_page_pointer(HANDLE citra_process, u8** page_table) {
	//[[[00007FF7EF00C0F0 + 48]]+60]

	u8* pointer_archive = 0;
	DWORD64 bytes_read = 0;
	
	//"citra-qt.exe"+1BFC1A0
	// input this string at [cheat engine -> add adress manually -> adress]
	// check 8byte and check hexadecimal
	// press OK
	// the value which this pointer points is the rax value

	pointer_archive = GetBasePointer(citra_process) + 0x1BFC1A0; //"citra-qt.exe"+1BFC1A0
	//you need to run the game if you want to find the page table properly

	//you will get the rax value by this readprocessmemory
	ReadProcessMemory(citra_process, (void*)pointer_archive, &pointer_archive, 8, &bytes_read);

	pointer_archive += 0x48;
	ReadProcessMemory(citra_process, (void*)pointer_archive, &pointer_archive, 8, &bytes_read);
	pointer_archive += 0;
	ReadProcessMemory(citra_process, (void*)pointer_archive, &pointer_archive, 8, &bytes_read);
	pointer_archive += 0x60;
	ReadProcessMemory(citra_process, (void*)pointer_archive, &pointer_archive, 8, &bytes_read);
	
	*page_table = pointer_archive;
	return 0;
}

const u32 CITRA_PAGE_SIZE = 0x1000;
const u32 CITRA_PAGE_MASK = CITRA_PAGE_SIZE - 1;
const int CITRA_PAGE_BITS = 12;
const std::size_t PAGE_TABLE_NUM_ENTRIES = 1 << (32 - CITRA_PAGE_BITS);

u8* GetPaddr(HANDLE citra_process, u8* page_table, u64 vaddr) {
	u8* page_pointer = page_table + (vaddr >> CITRA_PAGE_BITS) * 8;
	DWORD64 bytes_read = 0;

	ReadProcessMemory(citra_process, (void*)page_pointer, &page_pointer, 8, &bytes_read);
	return page_pointer + (vaddr & CITRA_PAGE_MASK);
}

u8* GetVaddr(HANDLE citra_process, u8* page_table, u64 paddr) {
	//return paddr from page_table
	for (u32 i = 0; i < PAGE_TABLE_NUM_ENTRIES; i++) {
		u8* page_pointer = page_table + (i) * 8;
		DWORD64 bytes_read = 0;

		ReadProcessMemory(citra_process, (void*)page_pointer, &page_pointer, 8, &bytes_read);

		if (paddr >= (u64)page_pointer && paddr < (u64)(page_pointer + CITRA_PAGE_SIZE)) {
			return (u8*)((i << CITRA_PAGE_BITS) + (paddr - (u64)page_pointer));
		}
	}
	return NULL;
}

int main(int argc, char** argv) {
	//std::cin.unsetf(std::ios::hex);

	char citra_window_name[256] = { 0, };
	char inital_value[256] = { 0, };

	TCHAR citra_window_name_t[256] = { 0, };
	
	std::cout << "finding citra window name..." << std::endl;

	while (1) {
		EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(citra_window_name));
		std::cout << citra_window_name << std::endl;

		if (strcmp(citra_window_name, inital_value)) {
			MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, citra_window_name, strlen(citra_window_name), citra_window_name_t, 256);
			//std::cout << citra_window_name_t << std::endl;
			break;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(3000));
	}

	HWND citra_window = FindWindow(NULL, citra_window_name_t);

	if (!citra_window) {
		std::cout << "cannot find window" << std::endl;
		return 0;
	}

	std::cout << "find citra window handle " << citra_window << std::endl;	

	DWORD process_id = 0;
	GetWindowThreadProcessId(citra_window, &process_id);

	std::cout << "got process id " << process_id << std::endl;

	HANDLE citra_process = OpenProcess(PROCESS_ALL_ACCESS, true, process_id);

	std::cout << "got process handle " << citra_process << std::endl;

	u8* page_table = 0;

	get_page_pointer(citra_process, &page_table);

	std::cout << "page table start point " << std::hex << (void*)(page_table) << std::endl;

	
	u64 vaddr_i = 0;
	std::cout << "input virtual adress: "; std::cin >> std::hex >> vaddr_i;
	
	u8* paddr_o = GetPaddr(citra_process, page_table, vaddr_i);
	std::cout << "got physical adress " << std::hex << (void*)(paddr_o) << std::endl;
	

	u64 paddr_i = 0;
	std::cout << "input physical adress: "; std::cin >> std::hex >> paddr_i;

	u8* vaddr_o = GetVaddr(citra_process, page_table, (u64)paddr_i);
	std::cout << "got virtual adress " << (void*)vaddr_o << std::endl;
	return 0;
}
