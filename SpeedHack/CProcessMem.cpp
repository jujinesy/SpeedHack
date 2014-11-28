#include "Windows.h"   
#include <Shlwapi.h>   
#include <tlhelp32.h>   
#include "aclapi.h"    

#include "CProcessMem.h"   

static BOOL EnableDebugPrivileges()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)){
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
	{
		CloseHandle(hToken);
		return false;
	}
	return true;
}
CProcessMem::_CProcessMem(int ProcessId)
{
	iProcessId = 0;
	SetProcessId(ProcessId);
}
CProcessMem::_CProcessMem(HANDLE ProcessHandle)
{
	iProcessId = 0;
	hProcess = ProcessHandle;
}
CProcessMem::~_CProcessMem()
{
	Close();
}
void CProcessMem::Close()
{
	if (iProcessId != 0) CloseHandle(hProcess);
	hProcess = NULL;
}
int CProcessMem::SetProcessId(int ProcessId)
{
	//close opened process handle first   
	Close();
	iProcessId = ProcessId;
	EnableDebugPrivileges();
	//get wow process handle, copy from wowsharp   
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
	if (hProcess == INVALID_HANDLE_VALUE || hProcess == NULL)
	{
		//UnSecProcess(ProcessId);   
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);
		if (hProcess == INVALID_HANDLE_VALUE || hProcess == NULL)
		{
			return false;
		}
	}
	//set new process id   
	iProcessId = ProcessId;
	return (int)hProcess;
}
DWORD CProcessMem::ReadDword(DWORD lpBaseAddress)
{
	DWORD dwRet = 0;
	ReadMemory(lpBaseAddress, &dwRet, 4);
	return dwRet;
}
bool CProcessMem::WriteDword(DWORD lpBaseAddress, DWORD dwValue)
{
	return WriteMemory(lpBaseAddress, &dwValue, 4);
}
bool CProcessMem::WriteMemory(DWORD lpBaseAddress, void * lpBuffer, DWORD dwSize)
{
	DWORD dwOldFlag;
	if (VirtualProtectEx(hProcess, (void *)lpBaseAddress, dwSize, PAGE_READWRITE, &dwOldFlag))
	{
		if (WriteProcessMemory(hProcess, (void *)lpBaseAddress, lpBuffer, dwSize, 0))
		{
			if (VirtualProtectEx(hProcess, (void *)lpBaseAddress, dwSize, dwOldFlag, &dwOldFlag))
			{
				return true;
			}
		}
	}
	return false;
}
bool CProcessMem::ReadMemory(DWORD lpBaseAddress, void * lpBuffer, DWORD dwSize)
{
	DWORD dwBytesRead;
	return (bool)ReadProcessMemory(hProcess, (void *)lpBaseAddress, lpBuffer, dwSize, &dwBytesRead);
}

LPVOID CProcessMem::VirtualAllocMem(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}