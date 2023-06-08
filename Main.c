#include "Header.h"


DWORD main()
{
	DWORD choice = 0, dwSession = 0, dwError = 1, Pid = 0;
	WCHAR KeepFile = 'Y', BruteforceTerminate = 'n', ShowKillableOnly = 'y', KillOption = 'y';
	WCHAR* service = (WCHAR*)malloc((MAX_PATH) * sizeof(WCHAR));
	WCHAR* ProcessToFind = (WCHAR*)malloc((MAX_PATH) * sizeof(WCHAR));
	WCHAR* InitialPath = (WCHAR*)malloc((MAX_PATH) * sizeof(WCHAR));
	WCHAR* filepath = NULL;
	WCHAR* StartingPath = NULL;

	__try {
		while (1)
		{
			choice = Menu();

			switch (choice)
			{
			case 1:
				TprintfC(White, L"Please select a file to lock.\n");
				filepath = (WCHAR*)malloc((MAX_PATH) * sizeof(WCHAR));
				filepath = SelectTargetFileByExplorer(TRUE);
				SimulateLockFile(filepath);
				ClearConsole();
				break;
			case 2:
				dwError = StartSession(&dwSession);
				// If a the user has simulated the lock of a file before
				if (filepath != NULL)
				{
					printf("Do you want to check the file you've just locked? (Y/n)\n");
					wscanf(L" %c", &KeepFile);
					if (KeepFile == 'n' || KeepFile == 'N')
					{
						filepath = SelectTargetFileByExplorer();
					}
				}
				else
				{
					TprintfC(White, L"Please select a file to register.\n");
					filepath = SelectTargetFileByExplorer();
				}
				RegisterFileResources(&dwSession, filepath);
				ClearConsole();
				break;

			case 3:
				dwError = StartSession(&dwSession);
				printf("Please enter the pid of the process you want to check.\n");
				scanf(" %d", &Pid);
				RegisterProcessResource(&dwSession, Pid, FALSE);
				ClearConsole();
				break;
			case 4:
				printf("Please enter the user friendly name of the target process you want to find.\n");
				wscanf(L" %[^\n]s", ProcessToFind);
				dwError = StartSession(&dwSession);
				SearchAndKillTarget(&dwSession, ProcessToFind, StartingPath);
				ClearConsole();
				break;
			case 5:
				GoThroughProc(1);
				ClearConsole();
				break;
			case 6:
				printf("Please enter the short name of the service you want to check.\n");
				wscanf(L" %[^\n]s", service);
				dwError = StartSession(&dwSession);
				RegisterServiceResource(&dwSession, service, FALSE);
				ClearConsole();
				break;
			case 7:
				GoThroughServices(TRUE);
				ClearConsole();
				break;
			default:
				__leave;
			}
		}
	}

	__finally
	{
		if (dwSession)
			RmEndSession(dwSession);
	}

	return 0;
}