#include <Windows.h>
#include <time.h>
#include <stdio.h>

#include "CtAes.h"

#pragma warning(disable : 4996) 

// -------------------------------- //// -------------------------------- //// -------------------------------- //

#define     	MIN_KEY_SIZE      2
#define		MAX_KEY_SIZE	128

BYTE EncryptSubmittedKey(IN PBYTE pKeyArray, IN SIZE_T sKeySize) {

    BYTE    HintByte 		= pKeyArray[1];
    BYTE    EncryptionByte 	= (rand() * pKeyArray[0]) % 0xFF;        

    for (int i = 0; i < sKeySize; i++)
        pKeyArray[i] = pKeyArray[i] ^ EncryptionByte;

    return HintByte;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

void PrintDecryptionFunc(IN BYTE bHintByte) {

    printf(
        "BYTE BruteForceDecryption(IN PBYTE pKeyArray, IN SIZE_T sKeySize) {\n\n"
        "\tint i = 0x00;\n\n"
        "\tfor (i = 0; i <= 0xFF; i++){\n\n"
        "\t\tif (((pKeyArray[1] ^ i) %% 0xFF) == 0x%0.2X) {\n"
        "\t\t\tbreak;\n"
        "\t\t}\n"
        "\t}\n\n"
        "\tfor (int x = 0; x < sKeySize; x++)\n"
        "\t\tpKeyArray[x] = pKeyArray[x] ^ i;\n\n"
        "\treturn i;\n"
        "}\n\n\n",
        bHintByte);
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL InstallAesEncryptionViaCtAes(IN PBYTE pRawDataBuffer, IN SIZE_T sRawBufferSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppCipherTextBuffer, OUT SIZE_T* psCipherTextSize) {

	if (!pRawDataBuffer || !sRawBufferSize || !ppCipherTextBuffer || !psCipherTextSize || !pAesKey || !pAesIv)
		return FALSE;

	PBYTE			pNewBuffer 		= pRawDataBuffer,
				pTmpCipherBuff 		= NULL;
	SIZE_T			sNewBufferSize	 	= sRawBufferSize;
	AES256_CBC_ctx		AesCtx 			= { 0x00 };

	if (sRawBufferSize % 16 != 0x00) {

		sNewBufferSize 	= sRawBufferSize + 16 - (sRawBufferSize % 16);
		pNewBuffer 	= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize);

		if (!pNewBuffer) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewBuffer, pRawDataBuffer, sRawBufferSize);
	}

	if (!(pTmpCipherBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));
	AES256_CBC_init(&AesCtx, pAesKey, pAesIv);
	AES256_CBC_encrypt(&AesCtx, (sNewBufferSize / 16), pTmpCipherBuff, pNewBuffer);

	*ppCipherTextBuffer 	= pTmpCipherBuff;
	*psCipherTextSize 	= sNewBufferSize;

	return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL ReadFileFromDiskA(IN LPCSTR cFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE		hFile	 		= INVALID_HANDLE_VALUE;
	DWORD		dwFileSize 		= NULL,
			dwNumberOfBytesRead 	= NULL;
	PBYTE		pBaseAddress	 	= NULL;

	if (!cFileName || !pdwFileSize || !ppFileBuffer)
		goto _END_OF_FUNC;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pBaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesRead, dwFileSize);
		goto _END_OF_FUNC;
	}

	*ppFileBuffer 	= pBaseAddress;
	*pdwFileSize 	= dwFileSize;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pBaseAddress && !*ppFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pBaseAddress);
	return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

// https://learn.microsoft.com/en-us/cpp/intrinsics/x64-amd64-intrinsics-list?view=msvc-170
extern int __cdecl _rdrand32_step(unsigned int*);

PBYTE GenerateRandomKey3(IN DWORD dwKeySize) {

	PBYTE			pKey 			= NULL;
	unsigned short		us2RightMostBytes 	= NULL;
	unsigned int		uiSeed 			= 0x00;
	BOOL			bResult 		= FALSE;

	if (!(pKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeySize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	us2RightMostBytes = (unsigned short)((ULONG_PTR)pKey & 0xFFFF);

	for (int i = 0; i < dwKeySize; i++) {

		if (!_rdrand32_step(&uiSeed))
			goto _END_OF_FUNC;

		if (i % 2 == 0)
			pKey[i] = (unsigned int)(((us2RightMostBytes ^ uiSeed) & 0xFF) % 0xFF);
		else
			pKey[i] = (unsigned int)((((us2RightMostBytes ^ uiSeed) >> 8) & 0xFF) % 0xFF);
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (!bResult && pKey) {
		HeapFree(GetProcessHeap(), 0x00, pKey);
		return NULL;
	}
	return pKey;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

VOID PrintHexArray(IN CONST CHAR* cArrayName, IN PBYTE pBufferData, IN SIZE_T sBufferSize) {

	printf("\nunsigned char %s[%d] = {", cArrayName, (int)sBufferSize);

	for (SIZE_T x = 0; x < sBufferSize; x++) {

		if (x % 16 == 0)
			printf("\n\t");

		if (x == sBufferSize - 1)
			printf("0x%0.2X", pBufferData[x]);
		else
			printf("0x%0.2X, ", pBufferData[x]);
	}

	printf("\n};\n");
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

int main(int argc, char* argv[]) {

    if (argc != 2)
        return -1;

	ULONG_PTR	uFileBuffer		= NULL;
	DWORD		dwFileSize		= 0x00;

	if (!ReadFileFromDiskA(argv[1], &uFileBuffer, &dwFileSize))
		return -1;

	PBYTE		pAESKey			= GenerateRandomKey3(32);
	PBYTE		pAESIv			= GenerateRandomKey3(16);
	ULONG_PTR	uCipheText		= NULL;
	SIZE_T		sCipherTextSize 	= NULL;

	if (!InstallAesEncryptionViaCtAes(uFileBuffer, dwFileSize, pAESKey, pAESIv, &uCipheText, &sCipherTextSize))
		return -1;

	BYTE	KeyHint		= EncryptSubmittedKey(pAESKey, 32);
	BYTE	IvHint		= EncryptSubmittedKey(pAESIv, 16);


	PrintHexArray("AESKey", pAESKey, 32);
	PrintHexArray("AESIv", pAESIv, 16);

	printf("\n\n");

	PrintHexArray("EncryptedShellcode", uCipheText, sCipherTextSize);

	printf("\n\n");

	PrintDecryptionFunc(KeyHint);
	PrintDecryptionFunc(IvHint);


    return 0;
}
