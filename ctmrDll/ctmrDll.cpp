// ctmrDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "ctmrDll.h"
#include <tchar.h>


// ���ǵ���������һ��ʾ��
// CTMRDLL_API int nctmrDll=0;
// 
// ���ǵ���������һ��ʾ����
// CTMRDLL_API int fnctmrDll(void)
// {
// 	return 42;
// }
// 
// �����ѵ�����Ĺ��캯����
// �й��ඨ�����Ϣ������� ctmrDll.h
// CctmrDll::CctmrDll()
// {
// 	return;
// }
DWORD _stdcall InitFunctionAddress()
{
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtdll == NULL)
        return 0;

    return (DWORD)GetProcAddress(hNtdll,"ZwOpenProcess");
}