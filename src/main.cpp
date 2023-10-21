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
#include<sstream>
#include<vector>

typedef int8_t u8; //1byte
typedef int16_t u16;
typedef int32_t u32;
typedef int64_t u64; //8byte

struct Citra {
	HANDLE hprocess;
	u8* page_table;
};

//--discarded--//
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
HANDLE GetProcessHandle() {
	//this method is discarded

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
			//std::wcout << citra_window_name_t << std::endl;
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

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, true, process_id);

	return hProcess;
}
//-------------//


HANDLE GetProcessHandleByEXE() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			//std::wcout << entry.szExeFile << std::endl;

			if (wcscmp(entry.szExeFile, L"citra-qt.exe") == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

				return hProcess;
			}
		}
	}

	return NULL;
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

u64 ReadCitraData(Citra citra, u64 vaddr, int d_size) {
	u8 data[8] = { 0, };
	DWORD64 bytes_read = 0;

	for (int i = 0; i < d_size; i++) {
		u8* paddr = GetPaddr(citra.hprocess, citra.page_table, vaddr - i); //assume Big Endian
		ReadProcessMemory(citra.hprocess, (void*)paddr, &data[i], 1, &bytes_read);
	}

	return *(u64*)data;
}

void WriteCitraData(Citra citra, u64 vaddr, u8* data, int d_size) {
	DWORD64 bytes_read = 0;

	for (int i = 0; i < d_size; i++) {
		u8* paddr = GetPaddr(citra.hprocess, citra.page_table, vaddr - i); //assume Big Endian
		WriteProcessMemory(citra.hprocess, (void*)paddr, &data[i], 1, &bytes_read);
	}
}

int MainCommand(Citra citra) {
	std::string command;
	std::cout << "> ";
	std::getline(std::cin, command);

	std::stringstream ss(command);
	std::string token;
	std::vector<std::string> tokens;

	while (ss >> token)
		tokens.push_back(token);

	if (tokens[0] == "quit") {
		//quit
		std::cout << "exit from program" << std::endl;
		return 0;
	}
	if (tokens[0] == "getp") {
		//getp [vaddr]
		u8* paddr = GetPaddr(citra.hprocess, citra.page_table, (u64)std::stoull(tokens[1], nullptr, 16));
		std::cout << "got physical adress " << std::hex << (void*)(paddr) << std::endl;
	}
	if (tokens[0] == "getv") {
		//getv [paddr]
		u8* vaddr = GetVaddr(citra.hprocess, citra.page_table, (u64)std::stoull(tokens[1], nullptr, 16));
		std::cout << "got virtual adress " << std::hex << (void*)vaddr << std::endl;
	}
	if (tokens[0] == "readv") {
		//readv [datasize] [vaddr]
		u64 data = ReadCitraData(citra, (u64)std::stoull(tokens[2], nullptr, 16), std::stoi(tokens[1]));
		std::cout << "read data " << std::dec << (unsigned long long)data << std::endl;
	}
	if (tokens[0] == "writev") {
		//writev [datasize] [data] [vaddr]
		u64 data = (u64)std::stoull(tokens[2]);
		WriteCitraData(citra, (u64)std::stoull(tokens[3], nullptr, 16), (u8*)&data, std::stoi(tokens[1]));
		std::cout << "write data " << std::dec << (unsigned long long)data << std::endl;
	}
}

int main(int argc, char** argv) {
	Citra citra; //hprocess & page_table

	citra.hprocess = GetProcessHandleByEXE();

	std::cout << "got process handle " << citra.hprocess << std::endl;

	get_page_pointer(citra.hprocess, &citra.page_table);

	std::cout << "page table start point " << std::hex << (void*)(citra.page_table) << std::endl;

	while (MainCommand(citra));

	//86CA6A8
	//86CA798

	return 0;
}
