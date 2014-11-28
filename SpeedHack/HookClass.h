#include <Psapi.h> 
#include "detours\\detours.h" 

/*
CCallHook
Class to change a call ***** code to new function
*/
typedef class _CCallHook{
private:
	CRITICAL_SECTION m_cs;
public:
	HANDLE hProcess;
	BYTE m_OldFunc[8];
	BYTE m_NewFunc[8];
	DWORD ptrCall;
	DWORD ptrOldfuction;
	DWORD ptrNewfuction;
	DWORD dwMemOldFlag;
	_CCallHook(HANDLE Process, DWORD CallPtr, DWORD NewFunc)
	{
		dwMemOldFlag = PAGE_READWRITE;
		hProcess = INVALID_HANDLE_VALUE;
		InitializeCriticalSection(&m_cs);
		if (Process == NULL)
			hProcess = GetCurrentProcess();
		else
			hProcess = Process;
		ptrNewfuction = NewFunc;
		ptrCall = CallPtr;
		Init();
	}
	~_CCallHook()
	{
		DeleteCriticalSection(&m_cs);
		SetHookOff();
		if (hProcess != INVALID_HANDLE_VALUE) CloseHandle(hProcess);
	}
	bool WINAPI Init()
	{
		DWORD dwOldFlag;
		if (VirtualProtectEx(hProcess, (void *)ptrCall, 4, PAGE_READWRITE, &dwOldFlag))
		{
			dwMemOldFlag = dwOldFlag;
			if (ReadProcessMemory(hProcess, (void *)ptrCall, m_OldFunc, 4, 0))
			{
				if (VirtualProtectEx(hProcess, (void *)ptrCall, 4, dwOldFlag, &dwOldFlag))
				{
					DWORD pNewFuncAddress;
					pNewFuncAddress = ptrNewfuction - ptrCall - 4;
					*(DWORD*)&m_NewFunc[0] = pNewFuncAddress;
					ptrOldfuction = *(int *)ptrCall + ptrCall + 4;
					return true;
				}
			}
		}
		return false;
	}
	bool WINAPI SetHookOn()
	{
		DWORD dwOldFlag;
		if (VirtualProtectEx(hProcess, (void *)ptrCall, 4, PAGE_READWRITE, &dwOldFlag))
		{
			if (WriteProcessMemory(hProcess, (void *)ptrCall, m_NewFunc, 4, 0))
			{
				if (VirtualProtectEx(hProcess, (void *)ptrCall, 4, dwOldFlag, &dwOldFlag))
				{
					return true;
				}
			}
		}
		return false;
	}
	bool WINAPI MemProtectOn()
	{
		DWORD dwOldFlag;
		if (VirtualProtectEx(hProcess, (void *)ptrCall, 4, dwMemOldFlag, &dwOldFlag))
		{
			return true;
		}
		return false;
	}
	bool WINAPI MemProtectOff()
	{
		DWORD dwOldFlag;
		if (VirtualProtectEx(hProcess, (void *)ptrCall, 4, PAGE_EXECUTE_READWRITE, &dwOldFlag))
		{
			return true;
		}
		return false;
	}
	bool WINAPI SetHookOff()
	{
		DWORD dwOldFlag;
		if (VirtualProtectEx(hProcess, (void *)ptrCall, 4, PAGE_READWRITE, &dwOldFlag))
		{
			if (WriteProcessMemory(hProcess, (void *)ptrCall, m_OldFunc, 4, 0))
			{
				if (VirtualProtectEx(hProcess, (void *)ptrCall, 4, dwOldFlag, &dwOldFlag))
				{
					return true;
				}
			}
		}
		return false;
	}
	//--------------------------------------------------------------------------- 
	void Lock(void) //for multi thread 
	{
		EnterCriticalSection(&m_cs);
	}
	//--------------------------------------------------------------------------- 
	void Unlock(void)
	{
		LeaveCriticalSection(&m_cs);
	}
	//----------------------------- 
}CCallHook;

/*
CJmpHook
Class like detours, to Hook function
Use detour function DetourCopyInstructionEx to disasm code
*/
#define MAX_COPY_CODE 20 
//#define JMP_CODE_SIZE 5 
typedef class _CJmpHook{
private:
	int iCopyLength;
	HANDLE hProcess;
	struct
	{
		char PushCode; // = 0x68; push ******** 
		DWORD FuncAddress;
		char RetnCode; // = 0xC3; 
	} m_NewFunc;
	BYTE m_CodeCopy[MAX_COPY_CODE];
	PBYTE ptrOldfuction;
	PBYTE ptrNewfuction;
	PBYTE ptrBridgeCode;
	CRITICAL_SECTION m_cs;

	bool WINAPI InitCopyCode()
	{
		//measure code size to copy 
		PBYTE pbSrc = m_CodeCopy;
		while (iCopyLength < sizeof(m_NewFunc) && iCopyLength < MAX_COPY_CODE)
		{
			LONG lExtra = 0;
			pbSrc = (PBYTE)DetourCopyInstructionEx(NULL, pbSrc, NULL, &lExtra);
			if (lExtra != 0) {
				return false;
			}
			if (pbSrc == m_CodeCopy) {
				return false;
			}
			iCopyLength = (LONG)(pbSrc - m_CodeCopy);
		}
		//init bridge code: jmp to old function + iCopyLength: (ptrOldfuction + iCopyLength) - (ptrBridgeCode + iCopyLength + 5); 
		m_CodeCopy[iCopyLength] = 0xE9;
		*((DWORD*)&m_CodeCopy[iCopyLength + 1]) = (DWORD)(ptrOldfuction - (ptrBridgeCode + 5));
		//init new function top code: jmp to new function 
		m_NewFunc.PushCode = 0x68;
		m_NewFunc.RetnCode = 0xC3;
		m_NewFunc.FuncAddress = (DWORD)ptrNewfuction;
		return true;
	}
public:
	_CJmpHook()
	{
		iCopyLength = 0;
		hProcess = INVALID_HANDLE_VALUE;
		InitializeCriticalSection(&m_cs);
	}
	~_CJmpHook()
	{
		SetHookOff();
		DeleteCriticalSection(&m_cs);
	}
	bool WINAPI InitLocal(PVOID * ppOldFuncPtr, PVOID pNewFuncPtr)
	{
		return 	InitRemote(NULL, ppOldFuncPtr, pNewFuncPtr, m_CodeCopy, MAX_COPY_CODE);
	}
	bool WINAPI InitRemote(HANDLE hTargetProcess, PVOID * ppOldFuncPtr, PVOID pNewFuncPtr, PBYTE pMemtoCopyCode, int iMemLength)
	{
		DWORD dwOldFlag;
		//check if has been inititiated 
		if (iCopyLength != 0) return false;
		//safety checck 
		if (ppOldFuncPtr == NULL || pNewFuncPtr == NULL) return false;
		if (hTargetProcess == GetCurrentProcess() || hTargetProcess == NULL)
		{
			hProcess = NULL;
			if (pMemtoCopyCode == NULL)
			{
				pMemtoCopyCode = m_CodeCopy;
				iMemLength = MAX_COPY_CODE;
			}
		}
		else if (pMemtoCopyCode == NULL || iMemLength < 10) return false;
		else
			hProcess = hTargetProcess;
		//set the varribles of this class  
		ptrOldfuction = (PBYTE)(*ppOldFuncPtr);
		ptrNewfuction = (PBYTE)pNewFuncPtr;
		ptrBridgeCode = (PBYTE)pMemtoCopyCode;
		//copy old code 
		if (!::VirtualProtectEx(hProcess, ptrOldfuction, MAX_COPY_CODE, PAGE_READWRITE, &dwOldFlag)) return false;
		if (!::ReadProcessMemory(hProcess, (LPCVOID)ptrOldfuction, m_CodeCopy, MAX_COPY_CODE, 0)) return false;
		if (!::VirtualProtectEx(hProcess, ptrOldfuction, MAX_COPY_CODE, dwOldFlag, &dwOldFlag)) return false;
		//set bridge code can be write and execute 
		if (!VirtualProtectEx(hProcess, ptrBridgeCode, MAX_COPY_CODE, PAGE_EXECUTE_READWRITE, &dwOldFlag)) return false;
		//init copy code memory 
		if (!InitCopyCode())  return false;
		//set pointer to call old function 
		*ppOldFuncPtr = ptrBridgeCode;
		printf("FuncAddress %X size %d\n", m_NewFunc.FuncAddress, sizeof(m_NewFunc));
		return true;
	}
	bool WINAPI SetHookOn()
	{
		DWORD dwOldFlag;
		//write code to bridge code space 
		if (ptrBridgeCode != (void *)m_CodeCopy)
		{
			if (!WriteProcessMemory(hProcess, (void *)ptrBridgeCode, m_CodeCopy, iCopyLength + 5, 0))
			{
				return false;
			}
		}
		if (VirtualProtectEx(hProcess, (void *)ptrOldfuction, sizeof(m_NewFunc), PAGE_READWRITE, &dwOldFlag))
		{
			if (WriteProcessMemory(hProcess, (void *)ptrOldfuction, &m_NewFunc, sizeof(m_NewFunc), 0))
			{
				if (VirtualProtectEx(hProcess, (void *)ptrOldfuction, sizeof(m_NewFunc), dwOldFlag, &dwOldFlag))
				{
					return true;
				}
			}
		}
		return false;
	}
	bool WINAPI SetHookOff()
	{
		DWORD dwOldFlag;
		if (VirtualProtectEx(hProcess, (void *)ptrOldfuction, sizeof(m_NewFunc), PAGE_READWRITE, &dwOldFlag))
		{
			if (WriteProcessMemory(hProcess, (void *)ptrOldfuction, m_CodeCopy, sizeof(m_NewFunc), 0))
			{
				if (VirtualProtectEx(hProcess, (void *)ptrOldfuction, sizeof(m_NewFunc), dwOldFlag, &dwOldFlag))
				{
					return true;
				}
			}
		}
		return false;
	}
	//--------------------------------------------------------------------------- 
	void Lock(void) //for multi thread 
	{
		EnterCriticalSection(&m_cs);
	}
	//--------------------------------------------------------------------------- 
	void Unlock(void)
	{
		LeaveCriticalSection(&m_cs);
	}
	//----------------------------- 
}CJmpHook;

/*
CApiIATHook
Class to hook dll api
*/
typedef class _CApiIATHook
{
public:
	PIMAGE_IMPORT_DESCRIPTOR LocationIAT(HMODULE hModule, LPCSTR szImportMod)
		//�뜸릎竊똦Module訝븃퓵葉뗦Æ�쀥룯�꾬폑szImportMod訝븃풏�ε틩�띸㎞�� 
	{
		//汝�ζ삸�╊맏DOS葉뗥틣竊뚦쫩��퓭�얧ULL竊뚦썱DOS葉뗥틣亦→쐣IAT�� 
		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
		if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
		//汝�ζ삸�╊맏NT�뉐퓱竊뚦맔�숃퓭�얧ULL�� 
		PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDOSHeader + (DWORD)(pDOSHeader->e_lfanew));
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) return NULL;
		//亦→쐣IAT烏ⓨ닕瓦붷썮NULL�� 
		if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) return NULL;
		//若싦퐤寧т�訝찳AT鵝띸쉰��  
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDOSHeader +
			(DWORD)(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
		//�방뜮渦볟뀯佯볟릫燁겼쑵����ζ��됬쉪IAT竊뚦쫩�백뀓�숃퓭�욆�IAT�겼�竊뚦맔�숁�役뗤툔訝訝찳AT�� 
		while (pImportDesc->Name)
		{
			//�룟룚瑥쩒AT�뤺염�꾥풏�ε틩�띸㎞�� 
			PSTR szCurrMod = (PSTR)((DWORD)pDOSHeader + (DWORD)(pImportDesc->Name));
			if (stricmp(szCurrMod, szImportMod) == 0) break;
			pImportDesc++;
		}
		if (pImportDesc->Name == NULL) return NULL;
		return pImportDesc;
	}
	DWORD HookAPIByName(LPCTSTR ModuleName, LPCSTR szImportMod, LPCSTR pcProcName, PROC pNewProc)
	{
		DWORD dRet = 0;
		HMODULE hModule = GetModuleHandle(ModuleName);
		if (!hModule) return 0;
		//若싦퐤szImportMod渦볟뀯佯볟쑉渦볟뀯�경뜮餘듕릎�껱AT�겼��� 
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = LocationIAT(hModule, szImportMod);
		if (pImportDesc == NULL) return FALSE;
		//寧т�訝챆hunk�겼��� 
		PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((DWORD)hModule + (DWORD)(pImportDesc->OriginalFirstThunk));
		//寧т�訝찳AT窈밭쉪Thunk�겼��� 
		PIMAGE_THUNK_DATA pRealThunk = (PIMAGE_THUNK_DATA)((DWORD)hModule + (DWORD)(pImportDesc->FirstThunk));
		//孃ょ렞�ζ돻熬ユ닼API�썸빊�껱AT窈뱄펽亮뜸슴�ⓩ쎘餓ｅ눦�겼쑑�岳�뵻�뜹쇈� 
		while (pOrigThunk->u1.Function)
		{
			//汝役뗦�Thunk��맔訝튘AT窈밤� 
			if ((pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) != IMAGE_ORDINAL_FLAG)
			{
				//�룟룚閭짪AT窈방��뤺염�꾢눦�겼릫燁겹� 
				PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)hModule + (DWORD)(pOrigThunk->u1.AddressOfData));
				if (pByName->Name[0] == '\0') return FALSE;
				//汝役뗦삸�╊맏�→닼�썸빊�� 
				if (strcmpi(pcProcName, (char*)pByName->Name) == 0)
				{
					MEMORY_BASIC_INFORMATION mbi_thunk;
					//�θ�岳�뵻窈든쉪岳→겘�� 
					VirtualQuery(pRealThunk, &mbi_thunk, sizeof(MEMORY_BASIC_INFORMATION));
					//�밧룜岳�뵻窈듕퓷�ㅵ콪�㏛맏PAGE_READWRITE�� 
					VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, PAGE_READWRITE, &mbi_thunk.Protect);
					//岳앭춼�잍씎�껦PI�썸빊�겼��� 
					dRet = pRealThunk->u1.Function;
					//岳�뵻API�썸빊IAT窈밧냵若밥맏�요빰�썸빊�겼��� 
					pRealThunk->u1.Function = (DWORD)pNewProc;
					//�℡쨳岳�뵻窈듕퓷�ㅵ콪�㎯� 
					DWORD dwOldProtect;
					VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, mbi_thunk.Protect, &dwOldProtect);
				}
			}
			pOrigThunk++;
			pRealThunk++;
		}
		SetLastError(ERROR_SUCCESS); //溫양쉰�숃�訝튓RROR_SUCCESS竊뚩〃鹽뷸닇�잆� 
		return dRet;
	}
}CApiIATHook;