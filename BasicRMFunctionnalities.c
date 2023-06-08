#pragma once
#include "Header.h"

//
// Tries to register in a RM session the file, to see what are the processes using it
// Returns an error code
//
DWORD RegisterFileResources(DWORD* dwSession, WCHAR* FilePath)
{
	char ShutDown = 'n';
	UINT nProcInfoNeeded, nProcInfo = 0;
	DWORD dwReason, dwError = 1;
	HANDLE hTargetProces = NULL;
	RM_PROCESS_INFO* RMProcInfo = NULL;

	// Register the file to check
	dwError = RmRegisterResources(*dwSession, 1, &FilePath, 0, NULL, 0, NULL);

	// Retrieves the appropriate number of affected apps & subsequently allocate the RM_PROCESS_INFO structures
	dwError = RmGetList(*dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);
	nProcInfo = nProcInfoNeeded;
	RMProcInfo = (RM_PROCESS_INFO*)calloc(nProcInfoNeeded + 1, sizeof(RM_PROCESS_INFO));

	// Retrieves the list of processes using the file
	dwError = RmGetList(*dwSession, &nProcInfoNeeded, &nProcInfo, RMProcInfo, &dwReason);
	if (dwError != ERROR_SUCCESS)
	{
		if (dwError != ERROR_SHARING_VIOLATION)
		{
			TprintfC(Red, L"[-] Error with RmGetList():%d, for path:%ws.\n", dwError, FilePath);
			return dwError;
		}
	}

	// If no process is currently using the resource
	if (nProcInfo == 0)
	{
		TprintfC(Green, L"[+] No process is blocking the resource.\n");
		return 0;
	}

	// Otherwise, displaying info of the affected apps 1 offer to terminate the affected app
	printf("\n ------- Applications using the file: ");
	TprintfC(Magenta, L"%ws.\n", FilePath);
	for (UINT i = 0; i < nProcInfo; i++)
	{
		DisplayInfo(RMProcInfo[i]);
	}

	// If at least one of the affected app is running
	if (AreAffectedAppsRunning(RMProcInfo, nProcInfo) == TRUE)
		TerminateAffectedApp(dwSession);

	return 0;
}

DWORD TerminateAffectedApp(DWORD* dwSession)
{
	//WCHAR* Shutdown = (WCHAR*)calloc(2,sizeof(WCHAR)); 

	WCHAR Shutdown = 'n';
	DWORD dwError = 0;

	// Offering to attempt to terminate the app 
	printf("\n\nDo you want to attempt to terminate the affected app(s)? (Y/n)\n");
	//wscanf(L" %[^\n]c", &Shutdown);
	wscanf(L" %wc%*wc", &Shutdown);

	if (Shutdown == 'y' || Shutdown == 'Y')
	{
		dwError = RmShutdown(*dwSession, 0x1, NULL);
		if (dwError != ERROR_SUCCESS)
		{
			TprintfC(Red, L"[-] Error with RmShutdown: %d.\n", dwError);
			return dwError;
		}

		TprintfC(Green, L"[+] The affected app(s) have been succesfully shutdown.\n");
	}
	return 0;
}

//
// Tries to register in a RM session the service based on the process id (a2), to see what are the processes using it
// If DetectLockerProc is set to TRUE, will not display the process itself, as it's common sense that a process locks itself
// Returns an error code
//
DWORD RegisterProcessResource(DWORD* dwSession, DWORD Pid, BOOL Enumerate)
{
	UINT i = 0;
	UINT nProcInfoNeeded = 0, nProcInfo = 0;
	DWORD dwReason, dwError = 1;
	HANDLE hTargetProces = NULL;
	RM_UNIQUE_PROCESS TargetProcess;
	RM_PROCESS_INFO* RMProcInfo = NULL;
	FILETIME lpExitTime, lpKernelTime, lpUserTime;
	FILETIME* CreationTime = (FILETIME*)malloc(1 * sizeof(FILETIME));
	char KillOption = 'n';

	// Retrieves information about the process to check, required to register the resource in the RM
	TargetProcess.dwProcessId = Pid;
	hTargetProces = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
	if (hTargetProces == NULL)
	{
		if (Enumerate == FALSE)
			TprintfC(Red, L"Error getting the handle of the process %d , error code: %d", Pid, GetLastError());
		return GetLastError();
	}

	dwError = GetProcessTimes(hTargetProces, CreationTime, &lpExitTime, &lpKernelTime, &lpUserTime);
	TargetProcess.ProcessStartTime = *CreationTime;
	if (dwError == 0)
	{
		if (Enumerate == FALSE)
			TprintfC(Red, L"Error getting the handle of the process %d , error code: %d", Pid, GetLastError());
		return GetLastError();
	}

	// Register the process to check
	dwError = RmRegisterResources(*dwSession, 0, NULL, 1, &TargetProcess, 0, NULL);
	if (dwError != ERROR_SUCCESS)
	{
		TprintfC(Red, L"[-] Error RmRegisterResources: %d", GetLastError());
		return GetLastError();
	}

	// Retrieves the list of processes using the service
	dwError = RmGetList(*dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);
	nProcInfo = nProcInfoNeeded;
	RMProcInfo = (RM_PROCESS_INFO*)calloc(nProcInfoNeeded, sizeof(RM_PROCESS_INFO));

	// Retrieves the list of processes using the file
	dwError = RmGetList(*dwSession, &nProcInfoNeeded, &nProcInfo, RMProcInfo, &dwReason);
	if (dwError == ERROR_SUCCESS)
	{
		if (nProcInfo == 0)
		{
			TprintfC(Green, L"[+] Something is weird\n");
			return 0;
		}
		if (Enumerate == TRUE && nProcInfo == 1)
		{
			TprintfC(Green, L"[+] No other process is blocking ");
			PrintProcessNameAndID(Pid);
			return 0;
		}
		// Display results
		printf("\n ------- Applications using process with pid ");
		PrintProcessNameAndID(Pid);
		for (i = 0; i < nProcInfo; i++)
		{
			DisplayInfo(RMProcInfo[i]);
		}

		// If the user explicitly entered the name of one app & that at least one of the affected app is running
		if (Enumerate == FALSE && AreAffectedAppsRunning(RMProcInfo, nProcInfo) == TRUE)
			TerminateAffectedApp(dwSession);
	}
	else
	{
		TprintfC(Red, L"[-] Error with RmGetList():%d.\n", dwError);
		return dwError;
	}
	nProcInfoNeeded = 0;
	nProcInfo = 0;
	free(RMProcInfo);
	return 0;
}

//
// Tries to register in a RM session the service based on the service name (a2), to see what are the processes using it
// If KillOption is set to TRUE, will offer the option to try to kill processes using the service through RmShutdown().
// Returns an error code
//
DWORD RegisterServiceResource(DWORD* dwSession, WCHAR* service, BOOL Enumerate)
{
	DWORD dwError, dwReason;
	UINT nProcInfoNeeded = 0, nProcInfo = 0;
	RM_PROCESS_INFO* RMProcInfo = NULL;

	if (Enumerate == FALSE)
		printf("[i] Information displayed might be incomplete if you did not launch TheRestarter as admin.\n");

	// Register the service to check
	dwError = RmRegisterResources(*dwSession, 0, NULL, 0, NULL, 1, (LPCWSTR*)&service);
	if (dwError)
	{
		TprintfC(Red, L"[-] Last error with RmRegisterResources(): %d.\n", dwError);
		return dwError;
	}

	// Retrieves the appropriate number of affected apps & subsequently allocate the RM_PROCESS_INFO structures
	dwError = RmGetList(*dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);
	nProcInfo = nProcInfoNeeded;
	RMProcInfo = (RM_PROCESS_INFO*)calloc(nProcInfoNeeded + 1, sizeof(RM_PROCESS_INFO));

	// Retrieves the list of processes using the file
	dwError = RmGetList(*dwSession, &nProcInfoNeeded, &nProcInfo, RMProcInfo, &dwReason);
	if (dwError != ERROR_SUCCESS)
	{
		if (dwError != ERROR_SHARING_VIOLATION)
		{
			TprintfC(Red, L"[-] Error with RmGetList():%d, for service:%ws.\n", dwError, service);
			return dwError;
		}
	}

	if (nProcInfo == 1 && Enumerate == TRUE)
	{
		TprintfC(Green, L"[+] No other application is blocking the resource:");
		TprintfC(Magenta, L"   %ws.\n", service);
		return 0;
	}

	// If affected apps, display info and offer to terminate them
	printf("\n ----------------- Applications using:");
	TprintfC(Magenta, L" %ws \n", service);

	for (UINT i = 0; i < nProcInfo; i++)
	{
		DisplayInfo(RMProcInfo[i]);
	}

	// If the user explicitly entered the name of one app & that at least one of the affected app is running
	if (Enumerate == FALSE && AreAffectedAppsRunning(RMProcInfo, nProcInfo) == TRUE)
		TerminateAffectedApp(dwSession);

	return 0;
}

//
//	Function to determine if one of the affected app is currently stopped
//	Returns TRUE if at least one app is currently runnin
BOOL AreAffectedAppsRunning(RM_PROCESS_INFO* RMProcInfo, DWORD nProcInfo)
{
	for (UINT i = 0; i < nProcInfo; i++)
	{
		// If the affected app is running
		if (RMProcInfo[i].AppStatus != RmStatusStopped && RMProcInfo[i].AppStatus != RmStatusStoppedOther)
			return TRUE;
	}

	return FALSE;
}