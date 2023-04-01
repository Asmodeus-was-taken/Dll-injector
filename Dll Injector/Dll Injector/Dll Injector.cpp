#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <subauth.h>
using namespace std;

DWORD procId;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef LONG NTSTATUS;
typedef HANDLE(WINAPI* OpenProcessFunc)(DWORD, BOOL, DWORD);
typedef NTSTATUS(NTAPI* NtOpenProcessFunc)(PHANDLE, ACCESS_MASK, _OBJECT_ATTRIBUTES, PCLIENT_ID);


int main()
{
    const wchar_t* exePath = L"Test.exe";
    SHELLEXECUTEINFOW shExecInfo = { 0 };
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
    shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExecInfo.lpFile = exePath;
    shExecInfo.nShow = SW_HIDE;

    if (ShellExecuteExW(&shExecInfo))
    {
        // wait for the process to start
        WaitForInputIdle(shExecInfo.hProcess, INFINITE);

        // get the process id of the started application
        GetWindowThreadProcessId(shExecInfo.hwnd, &procId);

        // print the process id
        std::cout << "Process ID: " << procId << std::endl;

        // close the process handle
        CloseHandle(shExecInfo.hProcess);
    }
    else
    {
        std::cerr << "Failed to execute the application." << std::endl;
    }


    DWORD pid = (DWORD)(GetProcessId("Test.exe"));
    if (pid == 0)
    {
        cout << "Target process not found." << endl;
        return 1;
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    // DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE ///
    //////////////////////////////////////////////////////////////////////////////////////////////////////////


    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    NtOpenProcessFunc NtOpenProcess = (NtOpenProcessFunc)GetProcAddress(ntdll, "NtOpenProcess");

    // Get the target process ID
    DWORD targetPid = pid; // Replace with the desired process ID

    // Prepare the required structures
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES), NULL, 0 };
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)targetPid;

    // Open the target process using NtOpenProcess
    HANDLE hProcess = NULL;
    NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, *(OBJECT_ATTRIBUTES*)&objAttr, &clientId);
    if (status == 0 && hProcess != NULL)
    {
        std::cout << "Successfully opened process with PID " << targetPid << std::endl;
        // Use the process handle
        // ...
        // Close the handle when done
        CloseHandle(hProcess);
    }
    else
    {
        std::cout << "Failed to open process with PID " << targetPid << std::endl;
    }

    // Clean up
    FreeLibrary(ntdll);

    //////////////////////////////////////////////////////////////////////////////////////////////////////////
   // DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE ///
   //////////////////////////////////////////////////////////////////////////////////////////////////////////


    // Allocate memory in the target process for the DLL path
    wchar_t dllPath[MAX_PATH] = L"dll.dll";


    LPVOID lpAddress = NULL;
    DWORD dwSize = 1024;
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, dwSize, NULL);
    lpAddress = MapViewOfFileEx(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, dwSize, NULL);
    CloseHandle(hMapping);

    // Check if memory allocation succeeded
    if (lpAddress == NULL) {
        std::cout << "Failed to allocate memory in target process" << std::endl;
        return 1;
    }

    // Write some data to the allocated memory
    memcpy(lpAddress, dllPath, sizeof(dllPath));

    // Free the memory allocation
    UnmapViewOfFile(lpAddress);
    CloseHandle(hProcess);


    //////////////////////////////////////////////////////////////////////////////////////////////////////////
   // DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE ///
   //////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Get the address of the LoadLibraryW function in kernel32.dll
    HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");

    PVOID lpBaseAddress = (PVOID)kernel32; // Replace with the actual base address

    // Unmap the memory region
    BOOL result = UnmapViewOfFileEx(lpBaseAddress,0);

    if (result == TRUE) {
        std::cout << "Memory region successfully freed." << std::endl;
    }
    else {
        std::cout << "Error freeing memory region: " << GetLastError() << std::endl;
    }

    // Close the process handle
    CloseHandle(hProcess);


    //////////////////////////////////////////////////////////////////////////////////////////////////////////
   // DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE DONE ///
   //////////////////////////////////////////////////////////////////////////////////////////////////////////




    LPVOID loadLibrary = (LPVOID)GetProcAddress(kernel32, "LoadLibraryW");
    if (loadLibrary == NULL)
    {
        cout << "Failed to get address of LoadLibraryW. Error code: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, lpAddress, sizeof(dllPath), MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

}