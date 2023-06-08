#pragma once
#include "Header.h"



DWORD CheckAffectedApps(LPWSTR InitialFilePath, LPCWSTR TargetProcess)
{
	DWORD dwReason, dwError = 1, dwSession = 0;
	UINT nProcInfoNeeded = 0, nProcInfo = 0;
	RM_PROCESS_INFO* RMProcInfo = NULL;

	StartSession(&dwSession);

	// Registers the file to check
	dwError = RmRegisterResources(dwSession, 1, (LPCWSTR*)&InitialFilePath, 0, NULL, 0, NULL);
	if (dwError != ERROR_SUCCESS)
	{
		TprintfC(Red, L"[-] Error with RmRegisterResources():%d.\n", dwError);
		RmEndSession(dwSession);
		return dwError;
	}

	// Retrieves the appropriate number of affected apps & subsequently allocate the RM_PROCESS_INFO structures
	dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);
	nProcInfo = nProcInfoNeeded;
	RMProcInfo = (RM_PROCESS_INFO*)calloc(nProcInfoNeeded + 1, sizeof(RM_PROCESS_INFO));

	// Retrieves the list of processes using the file
	dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, RMProcInfo, &dwReason);
	if (dwError != ERROR_SUCCESS)
	{
		TprintfC(Red, L"[-] Error with RmGetList():%d, for path:%ws.\n", dwError, InitialFilePath);
		RmEndSession(dwSession);
		return dwError;
	}

	if (nProcInfo == 0)
	{
		RmEndSession(dwSession);
		return 0;
	}

	// For each process that requires to be shut down
	for (UINT i = 0; i < nProcInfo; i++)
	{
		if ((wcsstr(_wcslwr(RMProcInfo[i].strAppName), _wcslwr(TargetProcess)) != NULL))
		{
			printf("> ");
			TprintfC(Magenta, L"%ws", InitialFilePath);
			printf(" blocked by: ");
			TprintfC(Magenta, L"%ws\n", RMProcInfo[i].strAppName);

			if (AreAffectedAppsRunning(RMProcInfo, nProcInfo) == TRUE)
				TerminateAffectedApp(&dwSession);

			RmEndSession(dwSession);
			return 1;
		}
	}
	RmEndSession(dwSession);
	return 0;
}

DWORD SearchForFilesLocked(LPCWSTR InitialPath, LPCWSTR TargetProcess)
{
	WIN32_FIND_DATAW FindFileData;
	HANDLE hFind = NULL;
	BOOL dwError = 1;
	DWORD Success = 0;

	LPWSTR FilePath = (WCHAR*)calloc(MAX_PATH, sizeof(WCHAR));
	WCHAR* RootPath = (WCHAR*)calloc(MAX_PATH, sizeof(WCHAR));

	// List of directories we do not need to check
	LPCWSTR self = L".";
	LPCWSTR upper = L"..";
	LPCWSTR Common = L"Common Files";
	LPCWSTR ExeExtension = L".exe";

	wcscpy(RootPath, InitialPath);
	wcscat(RootPath, L"\\*");
	hFind = FindFirstFileW((LPCWSTR)RootPath, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		dwError = GetLastError();
		if (dwError != ERROR_ACCESS_DENIED)
		{
			TprintfC(Red, L"[-] FindFirstFile failed: %d\n", GetLastError());
			return dwError;
		}

		else
			return 0;
	}

	do {
		// If this is a directory
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			// If this is not a blacklisted directory that doesn't need to be checked 
			if ((*FindFileData.cFileName != *self || *FindFileData.cFileName != *upper)
				&& (wcsstr(FindFileData.cFileName, Common) == NULL))
			{
				// Recreates the full path				
				wcscpy(FilePath, InitialPath);
				wcscat(FilePath, L"\\");
				wcscat(FilePath, FindFileData.cFileName);
				printf("Checking <DIR> %ws\\*\n", FilePath);

				// Search recursively the subdirectories
				if (SearchForFilesLocked(FilePath, TargetProcess) != 0)
					return GetLastError();
			}
		}
		// If this is a file
		else
		{
			if (wcsstr(FindFileData.cFileName, ExeExtension) != NULL)
			{
				// Recreates the full path
				wcscpy(FilePath, InitialPath);
				wcscat(FilePath, L"\\");
				wcscat(FilePath, FindFileData.cFileName);


				// Check the affected apps for the given resource
				if (CheckAffectedApps(FilePath, TargetProcess) != 0)
				{
					return GetLastError();
				}
			}
		}

		if (FindNextFileW(hFind, &FindFileData) == 0)
		{
			// If the function fails to find more files
			dwError = GetLastError();
			if (dwError != ERROR_NO_MORE_FILES)
				return dwError;
		}

		// checking there are still files to go through 
	} while (dwError != ERROR_NO_MORE_FILES);

	FindClose(hFind);
	return 0;
}


DWORD SearchAndKillTarget(DWORD* dwSession, LPCWSTR TargetProcess, LPCWSTR BeginSearch)
{
	DWORD  dwError = 0;
	BOOL Success = FALSE;
	DWORD  CharCount = MAX_PATH + 1;
	HANDLE hVolume = NULL;
	LPWSTR VolumePath = (WCHAR*)calloc(MAX_PATH, sizeof(WCHAR));
	LPWSTR VolumeName = (WCHAR*)calloc(MAX_PATH, sizeof(WCHAR));
	LPWSTR DriveLetter = (WCHAR*)calloc(3, sizeof(WCHAR));

	if (BeginSearch != NULL)
	{
		dwError = SearchForFilesLocked(BeginSearch, TargetProcess);
		return dwError;
	}
	else
	{
		// Gets the first volume
		hVolume = FindFirstVolumeW(VolumeName, MAX_PATH);
		if (hVolume == INVALID_HANDLE_VALUE)
			return GetLastError();

		do {
			// Gets the full name associated to the volume
			Success = GetVolumePathNamesForVolumeNameW(VolumeName, VolumePath, MAX_PATH, &CharCount);
			if (!Success)
				return GetLastError();

			// Saves only the letter (ie: C:)
			memcpy(DriveLetter, VolumePath, 2 * sizeof(WCHAR));

			dwError = SearchForFilesLocked(DriveLetter, TargetProcess);

			return 1;
			// Retrieves the next volume
			Success = FindNextVolumeW(hVolume, VolumeName, MAX_PATH);
			if (!Success)
			{
				dwError = GetLastError();
				if (dwError != ERROR_NO_MORE_FILES)
				{
					printf("FindNextVolumeW failed with error code %d\n", dwError);
					return dwError;
				}
			}

		} while (dwError != ERROR_NO_MORE_FILES);

		FindVolumeClose(hVolume);
	}

}


//
// Tries to enumerate services running in the system. If RegisterResource is TRUE, will register every service with RegisterProcessResource
// Returns an error code
//
DWORD GoThroughServices(BOOL RegisterResource)
{
	DWORD myPID = 0, dwSession;
	SC_HANDLE scMgr;
	DWORD additionalNeeded, dwError;
	DWORD cnt = 0;
	DWORD resume = 0;
	ENUM_SERVICE_STATUS_PROCESS  services[1024];

	printf("[i] Information displayed might be incomplete if you did not launch TheRestarter as admin.\n");

	myPID = GetCurrentProcessId();

	scMgr = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
	if (scMgr) {
		if (
			EnumServicesStatusEx(
				scMgr,
				SC_ENUM_PROCESS_INFO,        // Influences 5th parameter!
				SERVICE_WIN32_OWN_PROCESS,   // Service type (SERVICE_WIN32_OWN_PROCESS = services that run in their own process)
				SERVICE_STATE_ALL,           // Service state (ALL = active and inactive ones)
				(LPBYTE)services,
				sizeof(services),
				&additionalNeeded,
				&cnt,
				&resume,
				NULL                         // Group name
			))
		{
			TprintfC(Blue, L"\n PID \t\tService names\n");
			TprintfC(White, L"__________________________________________\n");
			for (DWORD i = 0; i < cnt; i++) {

				if (!RegisterResource)
				{
					TprintfC(White, L"%5d \t\t", services[i].ServiceStatusProcess.dwProcessId);
					TprintfC(Magenta, L"%ws\n", services[i].lpServiceName);
				}
				else
				{
					dwError = StartSession(&dwSession);
					if (dwError)
						return dwError;

					RegisterServiceResource(&dwSession, services[i].lpServiceName, TRUE);

					dwError = RmEndSession(dwSession);
					if (dwError != ERROR_SUCCESS)
					{
						TprintfC(Red, L"[-] Error with RmEndSession: %d.\n", GetLastError());
						return GetLastError();
					}
				}
			}
		}
		CloseServiceHandle(scMgr);
	}
	else if (GetLastError() == 5)
	{
		TprintfC(Red, L"[-] Access denied. Launch this as admin.\n");
		return GetLastError();
	}
	else {
		TprintfC(Red, L"[-] Error with OpenSCManager: %d.\n", GetLastError());
		return GetLastError();
	}

	return 0;
}

//
// Create a RM session 
//
DWORD StartSession(DWORD* dwSession)
{
	WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1];
	DWORD dwError = 1;
	//initialize the RM session's key
	memset(szSessionKey, 0, sizeof(szSessionKey));

	//starts the RM session and retrieves the session key
	dwError = RmStartSession(dwSession, 0, szSessionKey);

	if (dwError != ERROR_SUCCESS)
	{
		TprintfC(Red, L"[-] Error with RmStartSession: %d.\n", dwError);
		return dwError;
	}
	return 0;
}

//
// Tries to enumerate processes running in the system. If RegisterResource is TRUE, will register every process with RegisterProcessResource
// Returns an error code
//
DWORD GoThroughProc(BOOL RegisterResource)
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	UINT i;
	DWORD dwSession, dwError = 1;

	printf("[i] Information displayed might be incomplete if you did not launch TheRestarter as admin.\n");

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 0;
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	TprintfC(Blue, L"\nPID \t\t Process names\n");
	TprintfC(White, L"_____________________________________________________\n");
	// Print the name and process identifier for each process
	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			if (RegisterResource)
			{
				dwError = StartSession(&dwSession);
				if (dwError)
					return dwError;

				RegisterProcessResource(&dwSession, aProcesses[i], TRUE);

				dwError = RmEndSession(dwSession);
				if (dwError != ERROR_SUCCESS)
				{
					TprintfC(Red, L"[-] Error with RmEndSession: %d.\n", GetLastError());
					return GetLastError();
				}
			}
			else
			{
				PrintProcessNameAndID(aProcesses[i]);
			}
		}
	}
	return 0;
}

