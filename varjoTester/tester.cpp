#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <iostream>

#define BUFSIZE 4096
HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;
void CreateChildProcess(void);
void WriteToPipe(void);
void ReadFromPipe(void);
void ErrorExit(PCTSTR);

static bool kill(const std::string& processName)
{
#if defined(WIN32)        
    // Snapshot of the current processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
        return false;
    }

    char ansiProcName[1024];
    // Iterate
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32))
    {
        do {
            ansiProcName[0] = 0;
            DWORD dBufSize = WideCharToMultiByte(CP_OEMCP, 0, pe32.szExeFile, -1, NULL, 0, NULL, FALSE);
            int ret = WideCharToMultiByte(CP_OEMCP, 0, pe32.szExeFile, -1, ansiProcName, dBufSize, NULL, FALSE);
            if (ret <= 0)
                continue;

            if (_stricmp(ansiProcName, processName.c_str()) == 0)
            {
                // Found a process with the specified name, attempt to terminate it
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL)
                {
                    if (TerminateProcess(hProcess, 0))
                    {
                        std::cout << "Terminated process: " << pe32.szExeFile << std::endl;
                        CloseHandle(hProcess);
                        //CloseHandle(hSnapshot);
                        //return true;
                    }
                    else
                    {
                        std::cerr << "TerminateProcess failed with error code " << GetLastError() << std::endl;
                    }
                }
                else
                {
                    std::cerr << "OpenProcess failed with error code " << GetLastError() << std::endl;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    //std::cerr << "No process '" << processName << "' found." << std::endl;
    return true;
#else
    std::cerr << __PRETTY_FUNCTION__ << " - Not implemented" << std::endl;
    return false;
#endif        
}


int main(int argc, TCHAR* argv[])
{
    kill("InuService1.exe");

    SECURITY_ATTRIBUTES saAttr;
    printf("\n->Start of parent execution.\n");
    // Set the bInheritHandle flag so pipe handles are inherited.
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    // Create a pipe for the child process's STDOUT.
    if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
        ErrorExit(TEXT("StdoutRd CreatePipe"));
    }
    // Ensure the read handle to the pipe for STDOUT is not inherited.
    if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
        ErrorExit(TEXT("Stdout SetHandleInformation"));
    }
    // Create a pipe for the child process's STDIN.
    if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
        ErrorExit(TEXT("Stdin CreatePipe"));
    }
    // Ensure the write handle to the pipe for STDIN is not inherited.
    if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
        ErrorExit(TEXT("Stdin SetHandleInformation"));
    }
    // Create the child process.
    CreateChildProcess();
    // Read from pipe that is the standard output for child process.
    printf("\n->Contents of child process STDOUT:\n\n");
    ReadFromPipe();
    printf("\n->End of parent execution.\n");
    // The remaining open handles are cleaned up when this process terminates.
    // To avoid resource leaks in a larger application, close handles explicitly.
    return 0;
}
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
void CreateChildProcess()
{
    TCHAR szApplicationName[] = TEXT("C:\\Program Files\\Inuitive\\InuDev\\bin\\InuService1.exe");
    TCHAR szCommandLine[] = TEXT("\"C:\\Program Files\\Inuitive\\InuDev\\bin\\InuService1.exe\" console 3 m 1");
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    BOOL bSuccess = FALSE;
    DWORD flags = CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS;
    // Set up members of the PROCESS_INFORMATION structure.
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    // Set up members of the STARTUPINFO structure.
    // This structure specifies the STDIN and STDOUT handles for redirection.
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = g_hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
    // Create the child process.
    bSuccess = CreateProcess( //
        NULL,//szApplicationName,     // module name
        szCommandLine,         // command line
        NULL,                  // process security attributes
        NULL,                  // primary thread security attributes
        TRUE,                  // handles are inherited
        flags,                 // creation flags
        NULL,                  // use parent's environment
        NULL,                  // use parent's current directory
        &siStartInfo,          // STARTUPINFO pointer
        &piProcInfo);          // receives PROCESS_INFORMATION
    // If an error occurs, exit the application.
    if (!bSuccess) {
        ErrorExit(TEXT("CreateProcess"));
    }
    else {
        // Close handles to the child process and its primary thread.
        // Some applications might keep these handles to monitor the status
        // of the child process, for example.
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);
        // Close handles to the stdin and stdout pipes no longer needed by the child process.
        // If they are not explicitly closed, there is no way to recognize that the child process has ended.
        CloseHandle(g_hChildStd_OUT_Wr);
        CloseHandle(g_hChildStd_IN_Rd);
    }
}
// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT.
// Stop when there is no more data.
void ReadFromPipe(void)
{
    DWORD dwRead, dwWritten, dwAvail;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    for (;;) {

        //if (!PeekNamedPipe(g_hChildStd_OUT_Rd, NULL, NULL, &dwRead, &dwAvail, NULL) || dwAvail <= 0)
        //{
        //    //printf("no buffer....\n");
        //    continue;
        //}

        bSuccess = ReadFile(g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) {
            break;
        }
        bSuccess = WriteFile(hParentStdOut, chBuf, dwRead, &dwWritten, NULL);
        if (!bSuccess) {
            break;
        }
    }
}
// Format a readable error message, display a message box,
// and exit from the application.
void ErrorExit(PCTSTR lpszFunction)
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf) / sizeof(TCHAR), TEXT("%s failed with error %d: %s"), lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);
    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(1);
}