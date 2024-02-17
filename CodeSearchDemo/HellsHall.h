#include <Windows.h>

#ifndef HELLHALL_H
#define HELLHALL_H

typedef struct _NT_SYSCALL
{
    DWORD   dwSSn;
    PVOID   pSyscallAddress;
    PVOID   pSyscallInstAddress;

}NT_SYSCALL, * PNT_SYSCALL;


// From 'HellsHall.c'
BOOL    FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);
UINT32  CRC32BA(IN LPCSTR String);

// From 'HellsHallAsm.asm'
extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern      RunSyscall(VOID);


// Macro to call "SetSSn"
#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))
// Macro to call the hashing function (CRC32BA)
#define HASH(String)(CRC32BA((LPCSTR)String))

#endif // !HELLHALL_H



