// CodeCacheDetectionByCode.cpp : Defines the entry point for the console application.
//
// WinDBG
// pin.exe -- F:\Binarios\CodeCacheDetectionByCode.exe
// On x32dbg
// findallmem 01211000,90 90 50 58
// s - b 0 L ? 80000000 90 90 50 58

#include<stdlib.h>
#include "stdio.h"

// Origem: https://msdn.microsoft.com/pt-br/library/s58ftw19.aspx
#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION
#include <excpt.h>
#include <vector>
#include "MemUpdateMapInformations.h"

#include <string.h>

// De acordo com:
// https://www.blackhat.com/docs/asia-16/materials/asia-16-Sun-Break-Out-Of-The-Truman-Show-Active-Detection-And-Escape-Of-Dynamic-Binary-Instrumentation.pdf
// Signature can be certain code or data
// #define padrao 1

// ---------- start of eXait header modifications
#define DllExport extern "C" __declspec(dllexport)
DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

char* GetPluginName(void)
{
	static char PluginName[] = "CodeCacheDetectionByCode";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin implements a search function to search for a code pattern.";
	return MyDescription;
}
// ---------- end of eXait header modifications

// metodo a ser executado
void bait()
{
	// Default
	#ifndef padrao
	__asm {
		nop
		nop
		push eax
		pop eax
	}
	#endif
	// Padrao 1
	#ifdef padrao
	__asm {
		 mov ebx,0x12345678
	}
	#endif

	printf("\nbait() address: %x\n", &bait);
	printf("\nExecutou instrucoes asm\n");
}

unsigned char* search(int startAddress, int endAddress)
{
	unsigned char* data;
	data = (unsigned char*)startAddress;
	
	while(data < (unsigned char*)endAddress) {
		__try {		
			#ifndef padrao
			if (data[0] == 0x90 &&
				data[1] == 0x90 &&
				data[2] == 0x50 &&
				data[3] == 0x58)
			#endif
			#ifdef padrao
				if (data[0] == 0xBB &&
				data[1] == 0x78 &&
				data[2] == 0x56 &&
				data[3] == 0x34 &&
				data[4] == 0x12 )
			#endif
				 {
					printf("\nAchou padrao asm, @ 0x%x\n", data);
					return data;
				 }
			else {
				
				// http://stackoverflow.com/a/7319450
				#ifndef padrao
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x9090, endAddress - startAddress);
				#endif
				#ifdef padrao
					// 0x5678 Aparece invertido, ja que buscamos 0x7856
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x5678BB, endAddress - startAddress);
				#endif
			
				if (data_ == 0)
					return 0;
				else if(data == data_)
					return 0;
				else
					data = data_;
			}
		}
		//__except (filter(GetExceptionCode(), GetExceptionInformation())) {
		// Referencias: https://msdn.microsoft.com/pt-br/library/zazxh1a9.aspx
		// __except (puts("in filter"), EXCEPTION_EXECUTE_HANDLER) {
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return 0;
			continue;
		}
	// for 
	} 
	return 0;
}

unsigned char* search(int startAddress)
{
	unsigned char* data;

	int address = startAddress;
	int endAddress = 0x80000000 ;
	data = (unsigned char*)address;

	while(data < (unsigned char*)endAddress) {
		__try {
			#ifndef padrao
			if (data[0] == 0x90 &&
				data[1] == 0x90 &&
				data[2] == 0x50 &&
				data[3] == 0x58)
			#endif
			#ifdef padrao
				if (data[0] == 0xBB &&
				data[1] == 0x78 &&
				data[2] == 0x56 &&
				data[3] == 0x34 &&
				data[4] == 0x12 )
			#endif
				 {
					printf("\nAchou padrao asm, @ 0x%x\n", data);
					return data;
				 }
			else {
			
				// http://stackoverflow.com/a/7319450
				#ifndef padrao
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x9090, endAddress - startAddress);
				#endif
				#ifdef padrao
					// 0x5678 Aparece invertido, ja que buscamos 0x7856
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x5678BB, endAddress - startAddress);
				#endif
				if (data_ == 0)
					return 0;
				else if(data == data_)
					return 0;
				else
					data = data_;
			}
		}
		//__except (filter(GetExceptionCode(), GetExceptionInformation())) {
		// Referencias: https://msdn.microsoft.com/pt-br/library/zazxh1a9.aspx
		// __except (puts("in filter"), EXCEPTION_EXECUTE_HANDLER) {
		__except (EXCEPTION_EXECUTE_HANDLER) {
			continue;
		}

	} // for
	return 0;
}

void printMemoryInformations (std::vector<MEMPAGE> pageVector, int pageCount)
{
	char curMod[MAX_MODULE_SIZE] = "";

	 for(int i = pageCount - 1; i > -1; i--)
    {
		auto & currentPage = pageVector.at(i);
        if(!currentPage.info[0]) //there is a module
            continue; //skip non-modules
		 strcpy(curMod, pageVector.at(i).info);
		 printf("Informacoes da pagina %d : %s\t", i, curMod);
		DWORD newAddress = DWORD(currentPage.mbi.BaseAddress) + currentPage.mbi.RegionSize;
		printf("End Address 0x%x\n", newAddress);
	}
	 // system("pause");
}

// Padrao 0: 90 90 50 58 
// NOP 
// NOP 
// push   eax
// pop    eax

// Padrao 1: 78 56 34 12 
// mov ebx,0x12345678
int main(int argc, char** argv)
{
	unsigned char* primeiraOcorrenciaAddress = 0;
	unsigned char* segundaOcorrenciaAddress = 0;
	int (*ptbait)() = NULL;

	printf("Start ? \n\n");
	// system("pause");

	bait();
	ptbait = (int(*)())&bait;

	printf("Executou bait(); Continuar ? \n");
	// system("pause");

	// primeiraOcorrenciaAddress = search(&bait);
	primeiraOcorrenciaAddress = search((int)ptbait);
	printf("Endereco primeira ocorrencia: %x\n", primeiraOcorrenciaAddress);
	// system("pause");

	std::vector<MEMPAGE> pageVector = GetPageVector();

    int pagecount = (int)pageVector.size();
	
	// printMemoryInformations (pageVector, pageCount);
	 for(int i = 0; i < pagecount -1; i++)
    {
		auto & currentPage = pageVector.at(i);
        if(!currentPage.info[0]) //there is a module
            continue; //skip non-modules
		
		DWORD endAddress = DWORD(currentPage.mbi.BaseAddress) + currentPage.mbi.RegionSize;
		if ((int)(currentPage.mbi.BaseAddress) > (int)0x3000000)
			segundaOcorrenciaAddress = search((int)(currentPage.mbi.BaseAddress), (int)endAddress);

		if (segundaOcorrenciaAddress != 0 ) 
		{
			printf("Endereco segunda ocorrencia: %x\n", segundaOcorrenciaAddress);
			break;
		}
	}

	// system("pause");

	// Metodo lento
	/*segundaOcorrenciaAddress = search((int)(0x3000000 + primeiraOcorrenciaAddress));
	printf("Endereco segunda ocorrencia: %x\n", segundaOcorrenciaAddress);
	// system("pause");*/

    return 0;
}

int DoMyJob(void)
{
	unsigned char* primeiraOcorrenciaAddress = 0;
	unsigned char* segundaOcorrenciaAddress = 0;
	int (*ptbait)() = NULL;

	printf("Start ? \n\n");
	// system("pause");

	bait();
	ptbait = (int(*)())&bait;

	printf("Executou bait(); Continuar ? \n");
	// system("pause");

	// primeiraOcorrenciaAddress = search(&bait);
	primeiraOcorrenciaAddress = search((int)ptbait);
	printf("Endereco primeira ocorrencia: %x\n", primeiraOcorrenciaAddress);
	// system("pause");

	std::vector<MEMPAGE> pageVector = GetPageVector();

    int pagecount = (int)pageVector.size();
	
	// printMemoryInformations (pageVector, pageCount);
	 for(int i = 0; i < pagecount -1; i++)
    {
		auto & currentPage = pageVector.at(i);
        if(!currentPage.info[0]) //there is a module
            continue; //skip non-modules
		
		DWORD endAddress = DWORD(currentPage.mbi.BaseAddress) + currentPage.mbi.RegionSize;
		if ((int)(currentPage.mbi.BaseAddress) > (int)0x3000000)
			segundaOcorrenciaAddress = search((int)(currentPage.mbi.BaseAddress), (int)endAddress);

		if (segundaOcorrenciaAddress != 0 ) 
		{
			printf("Endereco segunda ocorrencia: %x\n", segundaOcorrenciaAddress);
			return 1;
			break;
		}
	}
	// system("pause");
    return 0;
}