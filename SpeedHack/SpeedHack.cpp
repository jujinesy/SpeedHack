// SpeedHack.cpp : 若싦퉱�㎩댍�겼틪�①쮮佯뤹쉪�ε룭�밤�   
//   
#pragma  pack (1)   

#include "windows.h"   
#include "stdio.h"   
#include "HookClass.h"   
#include "CProcessMem.h"   

#define offsetof(type, f) ((size_t)((char *)&((type *)0)->f - (char *)(type *)0))   

int SpeedHack(DWORD dwEnable, DWORD dwIncreaseFactor);
DWORD ReplaceAddr(char * buffer, DWORD dToFind, DWORD dRValue, int iBCount);
int CodeInject();

CProcessMem * WowProcessMem;


BOOL CodeInjected = FALSE;
BOOL HookEnabled = FALSE;
CJmpHook cjhGetTickCount;
CJmpHook cjhtimeGetTime;
CJmpHook cjhQueryPerformanceCounter;
CJmpHook cjhGetSystemTimeAsFileTime;
DWORD dwRemoteIncreaseFactorPtr = 0;
int iSpeedHackError = 0;


int main(int argc, char * argv[])
{
	char inBuff[32];
	int iProcessId, iSpeedFactor;
	printf("Type target process id:");
	gets(inBuff);
	iProcessId = atoi(inBuff);

	WowProcessMem = new CProcessMem(iProcessId);
	if (WowProcessMem == NULL)
	{
		printf("Can't open process.");
		return 0;
	}
	if (!CodeInjected)
	{
		if (CodeInject() < 0) return iSpeedHackError;
	}
	while (1)
	{
		printf("Type speed factor(e for exit):");
		gets(inBuff);
		if (strstr(inBuff, "e") != 0) break;
		iSpeedFactor = atoi(inBuff);
		SpeedHack(1, iSpeedFactor);
	}
	return 0;
}

#pragma comment(lib,"winmm.lib") //MMSYSTEM.H   

#define THREAD_SIZE 1024   
#define FUNC_COPY_SIZE 20   

typedef struct _SpeedHackData
{
	DWORD increasefactor;
	DWORD speedenabled;
	//global variables for QueryPerformanceCounter hook   
	DWORD qpc_last_fake, qpc_last_real;
	//global variables for timeGetTime hook   
	DWORD tgt_last_real, tgt_last_fake;
	//global variables for GetTickCount hook   
	DWORD gtc_last_real, gtc_last_fake;
	//global variables for GetTickCount hook   
	DWORD gstf_last_real, gstf_last_fake;
	char OpBuff_GetTickCount[FUNC_COPY_SIZE];
	char OpBuff_timeGetTime[FUNC_COPY_SIZE];
	char OpBuff_QueryPerformanceCounter[FUNC_COPY_SIZE];
	char OpBuff_GetSystemTimeAsFileTime[FUNC_COPY_SIZE];
}SpeedHackData;

typedef DWORD(WINAPI *MGetTickCount)();
typedef DWORD(WINAPI *MtimeGetTime)();
typedef BOOL(WINAPI *MQueryPerformanceCounter)(LARGE_INTEGER *lp);
typedef VOID(WINAPI *MGetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime);

static __declspec(naked) DWORD CodeStart()
{
	_asm{
		_emit 0x90
	}
}
static __declspec(naked) SpeedHackData * GetSpeedHackData()
{
	_asm{
		mov eax, 0xBBBBBBBB
			retn
	}
}
static DWORD WINAPI GetTickCount_Detour()
{
	SpeedHackData * shd = GetSpeedHackData();
	DWORD OldFunc = (DWORD)shd + offsetof(SpeedHackData, OpBuff_GetTickCount);
	DWORD ret = ((MGetTickCount)OldFunc)();

	DWORD nReal = ret;
	DWORD dReal = nReal - shd->gtc_last_real;
	DWORD dFake = (shd->increasefactor / 100) * dReal;

	if (shd->speedenabled == 1)
	{
		ret = shd->gtc_last_fake + dFake;
		shd->gtc_last_fake += dFake;
	}
	else
	{
		ret = shd->gtc_last_fake + dReal;
		shd->gtc_last_fake += dReal;
	}

	shd->gtc_last_real += dReal;

	return ret;
}

static DWORD WINAPI timeGetTime_Detour()
{
	SpeedHackData * shd = GetSpeedHackData();
	DWORD OldFunc = (DWORD)shd + offsetof(SpeedHackData, OpBuff_timeGetTime);
	DWORD ret = ((MtimeGetTime)OldFunc)();

	DWORD nReal = ret;
	DWORD dReal = nReal - shd->tgt_last_real;
	DWORD dFake = (shd->increasefactor / 100) * dReal;

	if (shd->speedenabled == 1)
	{
		ret = shd->tgt_last_fake + dFake;
		shd->tgt_last_fake += dFake;
	}
	else
	{
		ret = shd->tgt_last_fake + dReal;
		shd->tgt_last_fake += dReal;
	}

	shd->tgt_last_real += dReal;

	return ret;
}

static BOOL WINAPI QueryPerformanceCounter_Detour(LARGE_INTEGER *lp)
{
	SpeedHackData * shd = GetSpeedHackData();
	DWORD OldFunc = (DWORD)shd + offsetof(SpeedHackData, OpBuff_QueryPerformanceCounter);
	BOOL ret = ((MQueryPerformanceCounter)OldFunc)(lp);

	DWORD nReal = lp->LowPart;
	DWORD dReal = nReal - shd->qpc_last_real;
	DWORD dFake = (shd->increasefactor / 100) * dReal;

	if (shd->speedenabled == 1)
	{
		lp->LowPart = shd->qpc_last_fake + dFake;
		shd->qpc_last_fake += dFake;
	}
	else
	{
		lp->LowPart = shd->qpc_last_fake + dReal;
		shd->qpc_last_fake += dReal;
	}

	shd->qpc_last_real += dReal;

	return ret;
}
static VOID WINAPI GetSystemTimeAsFileTime_Detour(LPFILETIME lpSystemTimeAsFileTime)
{
	SpeedHackData * shd = GetSpeedHackData();
	DWORD OldFunc = (DWORD)shd + offsetof(SpeedHackData, OpBuff_QueryPerformanceCounter);
	((MGetSystemTimeAsFileTime)OldFunc)(lpSystemTimeAsFileTime);

	DWORD nReal = lpSystemTimeAsFileTime->dwLowDateTime;
	DWORD dReal = nReal - shd->gstf_last_real;
	DWORD dFake = (shd->increasefactor / 100) * dReal;

	if (shd->speedenabled == 1)
	{
		lpSystemTimeAsFileTime->dwLowDateTime = shd->gstf_last_fake + dFake;
		shd->gstf_last_fake += dFake;
	}
	else
	{
		lpSystemTimeAsFileTime->dwLowDateTime = shd->gstf_last_fake + dReal;
		shd->gstf_last_fake += dReal;
	}

	shd->gstf_last_real += dReal;

	return;
}
static DWORD CodeEnd()
{
	return 0;
}
VOID InitSpeedHackData(SpeedHackData * shdToInit)
{
	shdToInit->speedenabled = 1;
	shdToInit->increasefactor = 100;
}
int CodeInject()
{
	char tmpFuncCode[THREAD_SIZE];
	//allocc address for code   
	DWORD pRemoteThread = (DWORD)WowProcessMem->VirtualAllocMem(0, THREAD_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("Remote code start at 0x%X\n", pRemoteThread);
	if (!pRemoteThread) return FALSE;
	//init and write my reander function   
	DWORD dwCodeSize = (DWORD)CodeEnd - (DWORD)CodeStart;
	DWORD dwRemoteData = (DWORD)pRemoteThread + dwCodeSize;
	SpeedHackData * shdLocal = (SpeedHackData *)((DWORD)tmpFuncCode + dwCodeSize);
	//copy code   
	memcpy(tmpFuncCode, (void *)CodeStart, dwCodeSize);
	//set SpeedHackData address   
	if (!ReplaceAddr(tmpFuncCode, 0xBBBBBBBB, dwRemoteData, THREAD_SIZE))
	{
		iSpeedHackError = -901;
		return iSpeedHackError;
	}
	InitSpeedHackData(shdLocal);
	PVOID dwOldFuction = GetTickCount;
	DWORD dwNewFuction = (DWORD)pRemoteThread + ((DWORD)GetTickCount_Detour - (DWORD)CodeStart);
	printf("Hooking GetTickCount 0x%X, New:0x%X\n", dwOldFuction, dwNewFuction);
	if (!cjhGetTickCount.InitRemote(WowProcessMem->hProcess, &dwOldFuction, (LPVOID)dwNewFuction, (PBYTE)(dwRemoteData + offsetof(SpeedHackData, OpBuff_GetTickCount)), FUNC_COPY_SIZE)) return -9011;

	dwOldFuction = timeGetTime;
	dwNewFuction = (DWORD)pRemoteThread + ((DWORD)timeGetTime_Detour - (DWORD)CodeStart);
	printf("Hooking timeGetTime 0x%X, New:0x%X\n", dwOldFuction, dwNewFuction);
	if (!cjhtimeGetTime.InitRemote(WowProcessMem->hProcess, &dwOldFuction, (LPVOID)dwNewFuction, (PBYTE)(dwRemoteData + offsetof(SpeedHackData, OpBuff_timeGetTime)), FUNC_COPY_SIZE)) return -9012;

	dwOldFuction = QueryPerformanceCounter;
	dwNewFuction = (DWORD)pRemoteThread + ((DWORD)QueryPerformanceCounter_Detour - (DWORD)CodeStart);
	printf("Hooking QueryPerformanceCounter 0x%X, New:0x%X\n", dwOldFuction, dwNewFuction);
	if (!cjhQueryPerformanceCounter.InitRemote(WowProcessMem->hProcess, &dwOldFuction, (LPVOID)dwNewFuction, (PBYTE)(dwRemoteData + offsetof(SpeedHackData, OpBuff_QueryPerformanceCounter)), FUNC_COPY_SIZE)) return -9013;

	dwOldFuction = GetSystemTimeAsFileTime;
	dwNewFuction = (DWORD)pRemoteThread + ((DWORD)GetSystemTimeAsFileTime_Detour - (DWORD)CodeStart);
	printf("Hooking GetSystemTimeAsFileTime 0x%X, New:0x%X\n", dwOldFuction, dwNewFuction);
	if (!cjhGetSystemTimeAsFileTime.InitRemote(WowProcessMem->hProcess, &dwOldFuction, (LPVOID)dwNewFuction, (PBYTE)(dwRemoteData + offsetof(SpeedHackData, OpBuff_GetSystemTimeAsFileTime)), FUNC_COPY_SIZE)) return -9013;

	dwRemoteIncreaseFactorPtr = dwRemoteData + offsetof(SpeedHackData, increasefactor);
	//Write to remote process memory   

	if (!WowProcessMem->WriteMemory(pRemoteThread, tmpFuncCode, THREAD_SIZE))
	{
		iSpeedHackError = -902;
		return iSpeedHackError;
	}
	return (CodeInjected = TRUE);
}
int SpeedHack(DWORD dwEnable, DWORD dwIncreaseFactor)
{
	if (!WowProcessMem) return -900;

	if (dwEnable && !HookEnabled)
	{
		if (!cjhGetTickCount.SetHookOn()) return -911;
		if (!cjhtimeGetTime.SetHookOn()) return -912;
		if (!cjhQueryPerformanceCounter.SetHookOn()) return -913;
		if (!cjhGetSystemTimeAsFileTime.SetHookOn()) return -914;
		HookEnabled = TRUE;
	}
	if (!dwEnable && HookEnabled)
	{
		if (!cjhGetTickCount.SetHookOff()) return -915;
		if (!cjhtimeGetTime.SetHookOff()) return -916;
		if (!cjhQueryPerformanceCounter.SetHookOff()) return -917;
		if (!cjhGetSystemTimeAsFileTime.SetHookOn()) return -918;
		HookEnabled = FALSE;
	}

	if (!WowProcessMem->WriteDword(dwRemoteIncreaseFactorPtr, dwIncreaseFactor)) return -903;

	return 1;
}
DWORD ReplaceAddr(char * buffer, DWORD dToFind, DWORD dRValue, int iBCount)
{
	DWORD iReplaceCount = 0;
	for (int i = 0; i < iBCount - 4; i++) {
		if (*(DWORD *)&buffer[i] == dToFind)
		{
			*(DWORD *)&buffer[i] = dRValue;
			iReplaceCount++;
		}
	}
	return iReplaceCount;
}