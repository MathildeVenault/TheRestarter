#pragma once
#include "Header.h"


//
//	Graphic function to display the menu to the user and returns the option chosen by the user
//
DWORD Menu()
{
	DWORD choice = 0;

	TprintfC(Blue, L"\n ===============\n");
	TprintfC(Blue, L" ---- MENU -----");
	TprintfC(Blue, L"\n ===============\n");
	printf("\n-- Files --\n");
	printf("1. Simulate the lock of a file.\n");
	printf("2. Retrieve affected application of a target file.\n");
	printf("\n-- Processes --\n");
	printf("3. Retrieve affected applications of a target process (requires its pid).\n");
	printf("4. Search & attempt to kill a target process based on its name.\n");
	printf("5. Find processes currently used by more than one affected application.\n");
	printf("\n-- Services --\n");
	printf("6. Retrieve affected application of a target service (requires its short name).\n");
	printf("7. Find services currently used by more than one affected application.\n");
	printf("\nE. Exit\n");
	printf("> ");
	scanf(" %d", &choice);

	return choice;
}

//
//	Functionnality to clear the screen after the use of one feature
//
void ClearConsole()
{
	WCHAR continueB = 'b';

	printf("\n\n[i] Press any button to continue...\n");
	//scanf("  %c", &continueB);
	//wscanf(L" %[^\n]s", &continueB);
	wscanf(L" %wc%*wc", &continueB);
	system("cls");
	return;
}


//
//	Graphic function that displays the name of a process and its PID
//
void PrintProcessNameAndID(DWORD ProcessID)
{
	WCHAR szProcessName[MAX_PATH] = L"<unknown>";
	WCHAR whitelist[MAX_PATH] = L"<unknown>";
	HANDLE hProcess = NULL;

	//hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessID);
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessID);
	
	// Get the process name
	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));
		}
		// Print the process name and identifier.
		if (wcsstr(szProcessName, whitelist) == NULL)
		{
			TprintfC(White, L"%5d\t\t", ProcessID);
			TprintfC(Magenta, L"%ws\n", szProcessName);
		}
	}
	else
	{
		TprintfC(White, L"%5d\t\t", ProcessID);
		TprintfC(Red, L"[-] Error OpenProcess for process: %d.\n", GetLastError());
	}

	// Release the handle to the process.
	if (hProcess != NULL)
		CloseHandle(hProcess);

	return;
}

//
//	Graphic function that displays information about affected applications detected
//
void DisplayInfo(RM_PROCESS_INFO rgpi)
{

	if (rgpi.ApplicationType == RmService)
	{
		TprintfC(White, L"\n --- Service: ");
		TprintfC(Magenta, L"%ws ", rgpi.strServiceShortName);
		TprintfC(White, L"---- \n");
	}
	else
	{
		TprintfC(White, L"\n --- Process: ");
		TprintfC(Magenta, L"%ws ", rgpi.strAppName);
		TprintfC(White, L"---- \n");
	}

	TprintfC(Blue, L"| PID associated:");
	TprintfC(White, L" %d\n", rgpi.Process.dwProcessId);
	TprintfC(Blue, L"| Application Type:");
	TprintfC(White, L" %s\n", getRmAppType(rgpi.ApplicationType));
	TprintfC(Blue, L"| Application status:");
	TprintfC(White, L" %s\n", getRmAppStatus((RM_APP_STATUS)rgpi.AppStatus));
	TprintfC(Blue, L"| Application is restartable:");
	TprintfC(White, L" %s\n", getRmAppRestartable(rgpi.bRestartable));

	return;
}

// Custom printf with colors
VOID TprintfC(_In_ COLOR_TPRINTF Color, LPWSTR Format, ...) {

	va_list arglist;

	va_start(arglist, Format);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), Color); // Use the expected color
	vwprintf(Format, arglist);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), White); //get back to white police

	va_end(arglist);
}


// Functions to return the WCHAR string from a value of RM enumerations

const WCHAR* getRmRebootReason(RM_REBOOT_REASON RmRebootReason)
{
	switch (RmRebootReason)
	{
	case RmRebootReasonNone: return L"RmRebootReasonNone (A system restart is not required).";
	case RmRebootReasonPermissionDenied: return L"RmRebootReasonPermissionDenied (The current user does not have sufficient privileges to shut down one or more processes).";
	case RmRebootReasonSessionMismatch: return L"RmRebootReasonSessionMismatch (One or more processes are running in another Terminal Services session).";
	case RmRebootReasonCriticalProcess: return L"RmRebootReasonCriticalProcess (A system restart is needed because one or more processes to be shut down are critical processes).";
	case RmRebootReasonCriticalService: return L"RmRebootReasonCriticalService (A system restart is needed because one or more services to be shut down are critical services).";
	case RmRebootReasonDetectedSelf: return L"RmRebootReasonDetectedSelf (A system restart is needed because the current process must be shut down.)";
	default: return L"invalid value";
	}
}

const WCHAR* getRmAppType(RM_APP_TYPE RmAppType)
{
	switch (RmAppType)
	{
	case RmUnknownApp: return L"RmUnkownApp";
	case RmMainWindow: return L"RmMainWindow";
	case RmOtherWindow: return L"RmOtherWindow";
	case RmService: return L"RmService";
	case RmExplorer: return L"RmExplorer";
	case RmConsole: return L"RmConsole";
	case RmCritical: return L"RmCritical";
	default: return L"invalid value";
	}
}

const WCHAR* getRmAppStatus(RM_APP_STATUS RmAppStatus)
{
	switch (RmAppStatus)
	{
	case RmStatusUnknown: return L"RmStatusUnknown";
	case RmStatusRunning: return L"RmStatusRunning";
	case RmStatusStopped: return L"RmStatusStopped";
	case RmStatusStoppedOther: return L"RmStatusStoppedOther";
	case RmStatusRestarted: return L"RmStatusRestarted ";
	case RmStatusErrorOnStop: return L"RmStatusErrorOnStop";
	case RmStatusErrorOnRestart: return L"RmStatusErrorOnRestart";
	case RmStatusShutdownMasked: return L"RmStatusShutdownMasked";
	case RmStatusRestartMasked: return L"RmStatusRestartMasked ";
	default: return L"invalid value";
	}
}

const WCHAR* getRmAppRestartable(BOOL RmAppType)
{
	switch (RmAppType)
	{
	case 0: return L"false";
	case 1: return L"true";
	default: return L"invalid value";
	}
}