/*
Order:	To read and write process memory
*/
typedef class _CProcessMem
{
private:
	int		iProcessId;
	void	Close();
public:
	int GetProcessId(){ return iProcessId; }
	int SetProcessId(int ProcessId);
public:
	HANDLE  hProcess;
	_CProcessMem(int ProcessId);
	_CProcessMem(HANDLE ProcessHandle);
	~_CProcessMem();

	LPVOID VirtualAllocMem(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

	bool WriteMemory(DWORD lpBaseAddress, void * lpBuffer, DWORD dwSize);
	bool ReadMemory(DWORD lpBaseAddress, void * lpBuffer, DWORD dwSize);
	DWORD ReadDword(DWORD lpBaseAddress);
	bool WriteDword(DWORD lpBaseAddress, DWORD dwValue);
}CProcessMem;