// ctmrDllTest.cpp : �������̨Ӧ�ó������ڵ㡣
//
#include "stdafx.h"
#include "..\\ctmrDll\\ctmrDll.h"
#pragma comment(lib,"..\\ctmrDll\\Debug\\ctmrDll.lib")


int _tmain(int argc, _TCHAR* argv[])
{
    DWORD dwFunctionAddr = InitFunctionAddress();
    printf("dwFunctionAddr: 0x%8x\r\n",dwFunctionAddr);
    system("pause");
	return 0;
}

