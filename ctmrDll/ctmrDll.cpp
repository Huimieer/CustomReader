// ctmrDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "ctmrDll.h"
#include <tchar.h>
#include "resource.h"
/**/
#include "..\\CustomReader\\CommStruct.h"
#include "..\\CustomReader\\CtrlCmd.h"

/*�������ƺ��������ڵ�·��*/
#define CTMR_NAME       "CtmrReader"
#define CTMR_PATH       ".\\CtmrReader.sys"

#define DEVICE_NAME     "\\\\.\\CtmrReader"


const char DefaultProcessName[10] = "DNF.exe";
char gProcessName[MAX_PATH];

PFN_ZWOPENPROCESS pfnOriZwOpenProcess;
PFN_ZWREADVIRTUALMEMORY pfnOriZwReadVirtualMemory;
PFN_ZWWRITEVIRTUALMEMORY pfnOriZwWriteVirtualMemory;


//
//�ͷ�ָ������ԴID��ָ�����ļ�
//
BOOL _stdcall ReleaseResToFile(const char * lpszFilePath, DWORD dwResID, const char * resType)
{
    HMODULE hMod = GetModuleHandle(_T("ctmrDll.dll"));
    if (!hMod){
        OutputDebugStringA("GetModuleHandleW failed\r\n");
        return false;
    }
    HRSRC hSRC = FindResourceA(hMod, MAKEINTRESOURCEA(dwResID), resType);
    if (!hSRC){
        OutputDebugStringA("FindResourceW failed\r\n");
        return false;
    }
    DWORD dwSize    = 0;
    dwSize          = SizeofResource(hMod,hSRC);
    HGLOBAL hGloba  = LoadResource(hMod,hSRC);
    if (!hGloba){
        return false;
    }
    LPVOID lpBuffer = LockResource(hGloba);
    if (!lpBuffer){
        OutputDebugStringA("LockResource failed\r\n");
        return false;
    }
    HANDLE hFile    = CreateFileA(lpszFilePath,
        GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE){
        OutputDebugStringA("CreateFileA failed\r\n");
        return false;
    }
    DWORD dwWriteReturn;
    if (!WriteFile(hFile,
        lpBuffer,
        dwSize,
        &dwWriteReturn,
        NULL))
    {
        OutputDebugStringA("WriteFile failed\r\n");
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);
    return true;
}
//
//��������
//
BOOL _stdcall LoadDriver(const char * lpszDriverName,const char * lpszDriverPath)
{
    char szDriverImagePath[MAX_PATH] = {0};
    BOOL bRet                        = false;

    SC_HANDLE hServiceMgr            = NULL;//SCM�������ľ��
    SC_HANDLE hServiceDDK            = NULL;//NT��������ķ�����
    //�õ�����������·��
    GetFullPathNameA(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

    //�򿪷�����ƹ�����
    hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );

    if( hServiceMgr == NULL ){
        //OpenSCManagerʧ��
        OutputDebugStringA( "OpenSCManager() Failed! \r\n" );
        bRet = FALSE;
        goto BeforeLeave;
    }
    else{
        ////OpenSCManager�ɹ�
        OutputDebugStringA( "OpenSCManager() ok ! \n" );  
    }

    //������������Ӧ�ķ���
    hServiceDDK = CreateServiceA( hServiceMgr,
        lpszDriverName,         //�����������ע����е�����  
        lpszDriverName,         // ע������������ DisplayName ֵ  
        SERVICE_ALL_ACCESS,     // ������������ķ���Ȩ��  
        SERVICE_KERNEL_DRIVER,  // ��ʾ���صķ�������������  
        SERVICE_DEMAND_START,   // ע������������ Start ֵ  
        SERVICE_ERROR_IGNORE,   // ע������������ ErrorControl ֵ  
        szDriverImagePath,      // ע������������ ImagePath ֵ  
        NULL,  //GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList
        NULL,  
        NULL,  
        NULL,  
        NULL);  

    DWORD dwRtn;
    //�жϷ����Ƿ�ʧ��
    if( hServiceDDK == NULL ){  
        dwRtn = GetLastError();
        if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS ){  
            //��������ԭ�򴴽�����ʧ��
            OutputDebugStringA( "CrateService() Failed! \r\n" );  
            bRet = false;
            goto BeforeLeave;
        }  
        else{
            //���񴴽�ʧ�ܣ������ڷ����Ѿ�������
            OutputDebugStringA( "CrateService() Failed Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n" );  
        }

        // ���������Ѿ����أ�ֻ��Ҫ��  
        hServiceDDK = OpenServiceA( hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS );  
        if( hServiceDDK == NULL ){
            //����򿪷���Ҳʧ�ܣ�����ζ����
            dwRtn = GetLastError();  
            OutputDebugStringA( "OpenService() Failed! \r\n" );  
            bRet = FALSE;
            goto BeforeLeave;
        }  
        else{
            OutputDebugStringA( "OpenService() ok ! \n" );
        }
    }  
    else{
        OutputDebugStringA( "CrateService() ok ! \n" );
    }

    //�����������
    bRet = StartService( hServiceDDK, NULL, NULL );  
    if( !bRet ){  
        DWORD dwRtn = GetLastError();  
        if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING ){  
            OutputDebugStringA( "StartService() Failed! \r\n" );  
            bRet = false;
            goto BeforeLeave;
        }  
        else{  
            if( dwRtn == ERROR_IO_PENDING ){  
                //�豸����ס
                OutputDebugStringA( "StartService() Failed ERROR_IO_PENDING ! \r\n");
                bRet = false;
                goto BeforeLeave;
            }  
            else{  
                //�����Ѿ�����
                OutputDebugStringA( "StartService() Failed ERROR_SERVICE_ALREADY_RUNNING ! \r\n");
                bRet = false;
                goto BeforeLeave;
            }  
        }  
    }
    bRet = true;
    //�뿪ǰ�رվ��
BeforeLeave:
    if(hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if(hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;
}

//ж����������  
BOOL _stdcall UnloadDriver(const char * szSvrName )  
{
    BOOL bRet               = false;
    SC_HANDLE hServiceMgr   = NULL; //SCM�������ľ��
    SC_HANDLE hServiceDDK   = NULL; //NT��������ķ�����
    SERVICE_STATUS SvrSta;
    //��SCM������
    hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );  
    if( hServiceMgr == NULL ){
        //����SCM������ʧ��
        OutputDebugStringA( "OpenSCManager() Failed! \r\n");  
        bRet = false;
        goto BeforeLeave;
    }  
    else{
        //����SCM������ʧ�ܳɹ�
        OutputDebugStringA( "OpenSCManager() ok ! \n" );  
    }
    //����������Ӧ�ķ���
    hServiceDDK = OpenServiceA( hServiceMgr, szSvrName, SERVICE_ALL_ACCESS );  

    if( hServiceDDK == NULL ){
        //����������Ӧ�ķ���ʧ��
        OutputDebugStringA( "OpenService() Failed! \n");  
        bRet = false;
        goto BeforeLeave;
    }  
    else{  
        OutputDebugStringA( "OpenService() ok ! \n" );  
    }  
    //ֹͣ�����������ֹͣʧ�ܣ�ֻ�������������ܣ��ٶ�̬���ء�  
    if( !ControlService( hServiceDDK, SERVICE_CONTROL_STOP , &SvrSta ) ){  
        OutputDebugStringA( "ControlService() Failed!\n");  
    }  
    else{
        //����������Ӧ��ʧ��
        OutputDebugStringA( "ControlService() ok !\n" );  
    } 
    //��̬ж����������  
    if( !DeleteService( hServiceDDK ) )  
    {
        //ж��ʧ��
        OutputDebugStringA( "DeleteSrevice() Failed!\n");  
    }  
    else{  
        //ж�سɹ�
        OutputDebugStringA( "DelServer:deleteSrevice() ok !\n" );  
    }  

    bRet = true;
BeforeLeave:
    //�뿪ǰ�رմ򿪵ľ��
    if(hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if(hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;	
} 

HANDLE _stdcall OpenDevice()
{
    //������������  
    HANDLE hDevice = CreateFileA(DEVICE_NAME,  
        GENERIC_WRITE | GENERIC_READ,  
        0,  
        NULL,  
        OPEN_EXISTING,  
        0,  
        NULL);  
    if( hDevice == INVALID_HANDLE_VALUE ){
        return NULL;
    }
    return hDevice;
} 
//
//ͨ�Ų��Ժ���
//
BOOL _stdcall CommTest()
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;
    COMMTEST ct     = {0};
    DWORD dwRet     = 0;
    if(DeviceIoControl(hDevice,FC_COMM_TEST,NULL,0,&ct,sizeof(COMMTEST),&dwRet,NULL)){
        if (ct.success){
            bRet = true;
        }
    }
    CloseHandle(hDevice);
    return bRet;
}
//
//��ʼ��CustomReader 
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

    /*�ͷ�����sys����Դ����ǰĿ¼��*/
    if (!ReleaseResToFile(CTMR_PATH,IDR_SYS_CTMR,"SYS")){
        return false;
    }
    /*��������������ͨ��*/
    if(!LoadDriver(CTMR_NAME,CTMR_PATH)){
        /*ɾ�������ļ�*/
        DeleteFileA(CTMR_PATH);
        return false;
    }
    /*ɾ�������ļ�*/
    DeleteFileA(CTMR_PATH);

    if (!CommTest()){
        //ж������
        UnloadDriver(CTMR_NAME);
        return false;
    }

    /*����R3 hook*/



    return bRet;
}

//
//ж��customReader
//
void _stdcall UnloadCustomReader()
{
    UnloadDriver(CTMR_NAME);
}