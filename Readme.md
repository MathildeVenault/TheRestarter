# TheRestarter

Released alongside with the presentation at REcon 2023, TheRestarter is a tool is designed to interact with the Windows Restart Manager.

## Features 
- Register a file, a process or a service within a Restart Manager session to retrieve the list of affected applications (_applications currently using the resource_)
- Attempt to terminate the affected applications detected by the Restart Manager
- Automatically search & display for the list of services and processes that are currently used by applications other than themselves
- Iterate over the binaries of the system to determine if a target process is currently running
- Simulating the lock of a file (for a future file registration example)

## Build & run

#### Requirements
- Windows 10/ Windows 11
- Visual Studio 2022

#### Steps 
1. Dowload the sources files:

``` git clone https://github.com/MathildeVenault/TheRestarter.git```

2. Open .sln file in Visual Studio 2022
3. Compile with `x64`/``Release`` mode
4. (_Optional, to simulate file locking_) Copy `LockFile.exe` in the directory where your executable will be executed



## License

Published under the licence : [MIT](https://choosealicense.com/licenses/mit/)

Initial commit : version 0.1 (June, 2023.)
