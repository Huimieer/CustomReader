// ctmrDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "ctmrDll.h"
#include <tchar.h>
#include "resource.h"
#include ".\\mhook-lib\\mhook.h"

/**/
#include "..\\CustomReader\\CommStruct.h"
#include "..\\CustomReader\\CtrlCmd.h"

#define STATUS_SUCCESS                          (0x00000000L) // ntsubauth
#define STATUS_UNSUCCESSFUL                     (0xC0000001L)
#define STATUS_ACCESS_DENIED                    (0xC0000022L)
/*�������ƺ��������ڵ�·��*/
#define CTMR_NAME       "CtmrReader"
#define CTMR_PATH       ".\\CtmrReader.sys"

#define DEVICE_NAME     "\\\\.\\CtmrReader"

/*�ٵľ��ֵ*/
#define FAKE_HANDLE         (0x87654321)


const char DefaultProcessName[10] = "DNF.exe";
char gProcessName[MAX_PATH+1];

PFN_ZWOPENPROCESS pfnOriZwOpenProcess;
PFN_ZWREADVIRTUALMEMORY pfnOriZwReadVirtualMemory;
PFN_ZWWRITEVIRTUALMEMORY pfnOriZwWriteVirtualMemory;
//
//����������SSDT���е�������
//
DWORD gZwOpenProcessIndex;
DWORD gZwReadVirtualMemoryIndex;
DWORD gZwWriteVirtualMemoryIndex;

/*xp��*/
//mov     eax, 115h       ; NtWriteVirtualMemory
//mov     edx, 7FFE0300h
//call    dword ptr [edx]
//retn    14h

/*WIN7 32��*/
//mov     eax, 18Fh       ; NtWriteVirtualMemory
//mov     edx, 7FFE0300h
//call    dword ptr [edx]
//retn    14h

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

BOOL __stdcall avGetProcessName(NAMEINFO *pNameInfo)
{
    BOOL bRet       = false;
    DWORD dwRet     = 0;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;
    if (DeviceIoControl(hDevice,FC_GET_NAME_BY_ID,pNameInfo,sizeof(NAMEINFO),pNameInfo,sizeof(NAMEINFO),&dwRet,NULL)){
        bRet = true;
    }
    CloseHandle(hDevice);
    return bRet;
}

BOOL _stdcall avReadMemory(READMEM_INFO * PReadInfo)
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;
    DWORD dwRet     = 0;
    if (DeviceIoControl(hDevice,
        FC_READ_PROCESS_MEMORY,
        PReadInfo,
        sizeof(READMEM_INFO),
        PReadInfo,
        sizeof(READMEM_INFO),
        &dwRet,
        NULL))
    {
        bRet = true;
    }
    CloseHandle(hDevice);
    return bRet;
}

BOOL _stdcall avWriteMemory(WRITEMEM_INFO * PWriteInfo)
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;

    DWORD dwRet     = 0;
    if (DeviceIoControl(hDevice,
        FC_WRITE_PROCESS_MEMORY,
        PWriteInfo,
        sizeof(WRITEMEM_INFO),
        PWriteInfo,
        sizeof(WRITEMEM_INFO),
        &dwRet,
        NULL))
    {
        bRet = true;
    }
    CloseHandle(hDevice);

    return bRet;
}
//
//ģ��ntdll�еĺ���
//
__declspec(naked) NTSTATUS NTAPI  nakedZwOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId)
{
    __asm
    {
        mov     eax, gZwOpenProcessIndex
        mov     edx, 7FFE0300h
        call    dword ptr [edx]
        retn    10h
    }
}

__declspec(naked) NTSTATUS NTAPI nakedZwReadVirtualMemory(	
    HANDLE 	    ProcessHandle,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToRead,
    PSIZE_T 	NumberOfBytesRead )
{
    __asm
    {
        mov     eax, gZwReadVirtualMemoryIndex
        mov     edx, 7FFE0300h
        call    dword ptr [edx]
        retn    14h
    }
}

__declspec(naked) NTSTATUS NTAPI nakedZwWriteVirtualMemory(
    HANDLE 	    ProcessHandle,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToWrite,
    PSIZE_T 	NumberOfBytesWritten )
{
    __asm
    {
        mov     eax, gZwWriteVirtualMemoryIndex
        mov     edx, 7FFE0300h
        call    dword ptr [edx]
        retn    14h
    }
}

//
//�µ�nt����
//
NTSTATUS NTAPI  avZwOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId)
{
    if (ClientId){
        if (ClientId->UniqueProcess){
            /*ͨ��pid��ȡ��������*/
            NAMEINFO ni = {0};
            ni.dwPid    = (DWORD)ClientId->UniqueProcess;
            if (avGetProcessName(&ni)){
                if (_stricmp(gProcessName,ni.ProcessName) == 0){
                    //��������Ҫ��ע�Ľ��̣�ֻ����һ�� ��ֵ��������û��
                    *ProcessHandle = (HANDLE)FAKE_HANDLE;
                    return STATUS_SUCCESS;
                }
            }
        }
    }
    
    return nakedZwOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
}

NTSTATUS NTAPI  avZwReadVirtualMemory(	
    HANDLE 	    ProcessHandle,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToRead,
    PSIZE_T 	NumberOfBytesRead )
{
    if (ProcessHandle == (HANDLE)FAKE_HANDLE){
        /*���Ҫ��ȡ���ֽڴ��� MAX_BUFFER * 2�Ļ������ܶ�ȡ*/
        if (NumberOfBytesToRead > MAX_BUFFER_LENGTH*2){
            return STATUS_UNSUCCESSFUL;
        }
        //Ҫ��ȡ��ע���̵��ڴ�
        PREADMEM_INFO pri = new READMEM_INFO;
        if (pri == NULL)
            return STATUS_UNSUCCESSFUL;
        /*����*/
        memset(pri,0,sizeof(READMEM_INFO));

        strcpy_s(pri->ProcessName,MAX_BUFFER_LENGTH,gProcessName);
        pri->BaseAddress         = BaseAddress;
        pri->NumberOfBytesToRead = NumberOfBytesToRead;
        if (avReadMemory(pri)){
            memcpy_s(Buffer,NumberOfBytesToRead,pri->Buffer,NumberOfBytesToRead);
            *NumberOfBytesRead = pri->NumberOfBytesRead;
            delete pri;
            return STATUS_SUCCESS;
        }
    }
    return nakedZwReadVirtualMemory(ProcessHandle,BaseAddress,Buffer,NumberOfBytesToRead,NumberOfBytesRead);
}

NTSTATUS NTAPI avZwWriteVirtualMemory(
    HANDLE 	    ProcessHandle,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToWrite,
    PSIZE_T 	NumberOfBytesWritten )
{
    if (ProcessHandle == (HANDLE)FAKE_HANDLE){
        //Ҫд���ע���̵��ڴ�
        /*���Ҫд����ֽڴ��� MAX_BUFFER * 2�Ļ�������д��*/
        if (NumberOfBytesToWrite > MAX_BUFFER_LENGTH*2){
            return STATUS_UNSUCCESSFUL;
        }
        //Ҫд���ע���̵��ڴ�
        PWRITEMEM_INFO pwi = new WRITEMEM_INFO;
        if (pwi == NULL)
            return STATUS_UNSUCCESSFUL;
        /*����*/
        memset(pwi,0,sizeof(WRITEMEM_INFO));
        strcpy_s(pwi->ProcessName,MAX_BUFFER_LENGTH,gProcessName);
        pwi->BaseAddress          = BaseAddress;
        pwi->NumberOfBytesToWrite = NumberOfBytesToWrite;
        memcpy_s(pwi->Buffer,MAX_BUFFER_LENGTH*2,Buffer,NumberOfBytesToWrite);
        if (avWriteMemory(pwi)){
            *NumberOfBytesWritten = pwi->NumberOfBytesWritten;
            delete pwi;
            return STATUS_SUCCESS;
        }
    }
    return nakedZwWriteVirtualMemory(ProcessHandle,BaseAddress,Buffer,NumberOfBytesToWrite,NumberOfBytesWritten);
}
//
//��ʼ��CustomReader 
//
BOOL _stdcall InitCustomReader(const char *ProcessName)
{
    BOOL bRet = false;
    /*��ʼ����Ϸ������*/
    memset(gProcessName,0,MAX_PATH+1);
    if (ProcessName == NULL){
        //Ĭ�����dnf
        memcpy_s(gProcessName,MAX_PATH+1,DefaultProcessName,strlen(DefaultProcessName)+1);
    }
    else{
        memcpy_s(gProcessName,MAX_PATH+1,ProcessName,strlen(ProcessName)+1);
    }

    /*���ntdll�е���غ�����ԭʼ��ַ*/
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtdll == NULL)
        return false;
    pfnOriZwOpenProcess         = (PFN_ZWOPENPROCESS)GetProcAddress(hNtdll,"ZwOpenProcess");
    pfnOriZwReadVirtualMemory   = (PFN_ZWREADVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwReadVirtualMemory");
    pfnOriZwWriteVirtualMemory  = (PFN_ZWWRITEVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwWriteVirtualMemory");
    /*��ȡ������*/
    gZwOpenProcessIndex         = *(DWORD *)((DWORD)pfnOriZwOpenProcess + 1);
    gZwReadVirtualMemoryIndex   = *(DWORD *)((DWORD)pfnOriZwReadVirtualMemory + 1);
    gZwWriteVirtualMemoryIndex  = *(DWORD *)((DWORD)pfnOriZwWriteVirtualMemory + 1);

    /*�ͷ�����sys����Դ����ǰĿ¼��*/
    if (!ReleaseResToFile(CTMR_PATH,IDR_SYS_CTMR,"SYS")){
        return false;
    }
    /*��������������ͨ��*/
    //if(!LoadDriver(CTMR_NAME,CTMR_PATH)){
    //    /*ɾ�������ļ�*/
    //    DeleteFileA(CTMR_PATH);
    //    return false;
    //}
    /*ɾ�������ļ�*/
    DeleteFileA(CTMR_PATH);

    //if (!CommTest()){
    //    //ж������
    //    UnloadDriver(CTMR_NAME);
    //    return false;
    //}

    /*����R3 hook*/
    Mhook_SetHook((PVOID*)&pfnOriZwOpenProcess,avZwOpenProcess);
    Mhook_SetHook((PVOID*)&pfnOriZwReadVirtualMemory,avZwReadVirtualMemory);
    Mhook_SetHook((PVOID*)&pfnOriZwWriteVirtualMemory,avZwWriteVirtualMemory);


    return bRet;
}

//
//ж��customReader
//
void _stdcall UnloadCustomReader()
{
    //UnloadDriver(CTMR_NAME);
    Mhook_Unhook((PVOID*)&pfnOriZwOpenProcess);
    Mhook_Unhook((PVOID*)&pfnOriZwReadVirtualMemory);
    Mhook_Unhook((PVOID*)&pfnOriZwWriteVirtualMemory);
}