// ctmrDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "ctmrDll.h"
#include <tchar.h>
/**/
#include "..\\CustomReader\\CommStruct.h"
#include "..\\CustomReader\\CtrlCmd.h"

const char DefaultProcessName[10] = "DNF.exe";
char gProcessName[MAX_PATH];

PFN_ZWOPENPROCESS pfnOriZwOpenProcess;
PFN_ZWREADVIRTUALMEMORY pfnOriZwReadVirtualMemory;
PFN_ZWWRITEVIRTUALMEMORY pfnOriZwWriteVirtualMemory;

//
//
//
BOOL _stdcall InitCustomReader(const char *ProcessName)
{
    BOOL bRet = false;
    /*��ʼ����Ϸ������*/
    memset(gProcessName,0,MAX_PATH);
    if (ProcessName == NULL){
        //Ĭ�����dnf
        memcpy_s(gProcessName,MAX_PATH,DefaultProcessName,strlen(DefaultProcessName)+1);
    }
    else{
        memcpy_s(gProcessName,MAX_PATH,ProcessName,strlen(ProcessName)+1);
    }

    /*���ntdll�е���غ�����ԭʼ��ַ*/
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtdll == NULL)
        return false;
    pfnOriZwOpenProcess         = (PFN_ZWOPENPROCESS)GetProcAddress(hNtdll,"ZwOpenProcess");
    pfnOriZwReadVirtualMemory   = (PFN_ZWREADVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwReadVirtualMemory");
    pfnOriZwWriteVirtualMemory  = (PFN_ZWWRITEVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwWriteVirtualMemory");

    /*��������������ͨ��*/

    return bRet;
}

void _stdcall UnloadCustomReader()
{

}