#pragma once

#include <windows.h>
#include <restartManager.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <conio.h>
#include <string.h>
#include <errors.h>
#include <tlhelp32.h>
#include <WinCon.h>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "rstrtmgr.lib")
#pragma warning(disable:4996)



static BOOL debug_mode = 0;

typedef enum _COLOR_TPRINTF {

	Red = 12,
	Blue = 11,
	Green = 10,
	Magenta = 5,
	White = 15,
	Yellow = 14

} COLOR_TPRINTF;


// Graphic functions 
VOID TprintfC(_In_ COLOR_TPRINTF Color, LPWSTR Format, ...);

void DisplayInfo(RM_PROCESS_INFO rgpi);

void ClearConsole();

void PrintProcessNameAndID(DWORD processID);

DWORD Menu();


// Utilitary functions
DWORD SimulateLockFile(WCHAR* FilePath);

WCHAR* SelectTargetFileByExplorer();

BOOL AreAffectedAppsRunning(RM_PROCESS_INFO* RMProcInfo, DWORD nProcInfo);

const WCHAR* getRmRebootReason(RM_REBOOT_REASON RmRebootReason);

const WCHAR* getRmAppType(RM_APP_TYPE RmAppType);

const WCHAR* getRmAppStatus(RM_APP_STATUS RmAppStatus);

const WCHAR* getRmAppRestartable(BOOL RmAppType);



// Basic functionnalities of the Restart Manager
DWORD StartSession(DWORD* dwSession);

DWORD RegisterProcessResource(DWORD* dwSession, DWORD Pid, BOOL Enumerate);

DWORD RegisterFileResources(DWORD* dwSession, WCHAR* filepath);

DWORD RegisterServiceResource(DWORD* dwSession, WCHAR* service, BOOL Enumerate);

DWORD TerminateAffectedApp(DWORD* dwSession);

// Advanced functionnalities
DWORD GoThroughProc(BOOL RegisterResource);

DWORD GoThroughServices(BOOL RegisterResource);

DWORD SearchAndKillTarget(DWORD* dwSession, LPCWSTR TargetProcess, LPCWSTR BeginSearch);

DWORD CheckAffectedApps(LPWSTR InitialFilePath, LPCWSTR TargetProcess);

DWORD SearchForFilesLocked(LPCWSTR InitialPath, LPCWSTR TargetProcess);
