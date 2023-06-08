#pragma once
#include "Header.h"

//
//	Simulates the lock of the file given in arugments creating a process from the binary "LockFile.exe"
//	/!\ LockFile.exe has to be in the same directory as the current executable
//	Returns 0 if successful, or an error code if any
//
DWORD SimulateLockFile(WCHAR* FilePath)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	WCHAR* AppPath = NULL;
	WCHAR* CurrentAppPath = (WCHAR*)malloc((MAX_PATH) * sizeof(WCHAR));
	WCHAR* cursor = (WCHAR*)malloc((MAX_PATH) * sizeof(WCHAR));
	size_t LenghtDir = 0;

	if (!GetModuleFileNameW(NULL, CurrentAppPath, MAX_PATH))
	{
		TprintfC(Red, L"[-] Error: GetCurrentDirectory has failed %d.\n", GetLastError());
		return GetLastError();
	}
	// Find the lenght of the current directory
	cursor = wcsrchr(CurrentAppPath, '\\');
	LenghtDir = wcslen(CurrentAppPath) - wcslen(cursor);

	// Copy the current directory
	AppPath = (WCHAR*)calloc((LenghtDir + wcslen(L"\\LockFile.exe") - 1), sizeof(WCHAR));
	memcpy(AppPath, CurrentAppPath, LenghtDir * sizeof(WCHAR));

	// Append the name of the executable locking file
	memcpy(AppPath + LenghtDir, L"\\LockFile.exe", wcslen(L"\\LockFile.exe") * sizeof(WCHAR));

	printf("[+] Using binary: %ws.\n", AppPath);

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Start the child process. 
	if (!CreateProcessW(AppPath,
		FilePath,
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		return 1;
	}

	TprintfC(Green, L"[+] Process succesfully started in another process.\n");

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}


//
//	Spawns a interactive explorer to allow the user to select a file, and returns the path of the file chosen
//
WCHAR* SelectTargetFileByExplorer()
{
	OPENFILENAME ofn;
	WCHAR* Output = (WCHAR*)malloc((MAX_PATH) * sizeof(WCHAR));

	if (SecureZeroMemory(&ofn, sizeof(OPENFILENAME)) == NULL)
	{
		TprintfC(Red, L"[-] Error SecureZeroMemory() %d", GetLastError());
		return NULL;
	}

	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = Output;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"All\0*.*\0Text\0*.pf\0*.db\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileNameW(&ofn) != TRUE)
	{
		TprintfC(Red, L"[-] Error: GetOpenFileName has failed %d.\n", GetLastError());
	}

	return Output;
}