#pragma once
// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� CTMRDLL_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// CTMRDLL_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
// #ifdef CTMRDLL_EXPORTS
// #define CTMRDLL_API __declspec(dllexport)
// #else
// #define CTMRDLL_API __declspec(dllimport)
// #endif



//extern CTMRDLL_API int nctmrDll;

//CTMRDLL_API int fnctmrDll(void);
DWORD _stdcall InitFunctionAddress();
