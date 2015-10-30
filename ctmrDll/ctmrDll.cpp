// ctmrDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include "ctmrDll.h"
#include <tchar.h>
#include "resource.h"
#include <TlHelp32.h>
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

#define DEVICE_NAME     "\\\\.\\ReaderSymLink"

/*�ٵľ��ֵ*/
#define FAKE_HANDLE         (0x87654321)
//��ע�Ľ���
DWORD gGamePid = 0;

HANDLE gGameHandle = INVALID_HANDLE_VALUE;

/*����֮���*/
const char GameProcessName[20] = "ITM6n�p";
//char gProcessName[MAX_PATH+1];

PFN_ZWDEVICEIOCONTROLFILE pfnOriZwDeviceIoControlFile;
PFN_ZWOPENPROCESS pfnOriZwOpenProcess;
PFN_ZWREADVIRTUALMEMORY pfnOriZwReadVirtualMemory;
PFN_ZWWRITEVIRTUALMEMORY pfnOriZwWriteVirtualMemory;
PFN_ZWQUERYVIRTUALMEMORY pfnOriZwQueryVirtualMemory;
//
//����������SSDT���е�������
//
DWORD gZwOpenProcessIndex;
DWORD gZwReadVirtualMemoryIndex;
DWORD gZwWriteVirtualMemoryIndex;
DWORD gZwDeviceIoControlFileIndex;
DWORD gZwQueryVirtualMemoryIndex;

//
//ͨ����������ȡ����id
//
DWORD GetProcessIdByName(wchar_t * wszName);

BOOL __stdcall MyDeviceIoControl(
    HANDLE       hDevice,
    DWORD        dwIoControlCode,
    LPVOID       lpInBuffer,
    DWORD        nInBufferSize,
    LPVOID       lpOutBuffer,
    DWORD        nOutBufferSize,
    LPDWORD      lpBytesReturned,
    LPOVERLAPPED lpOverlapped
    );

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

inline void __cdecl DbgPrint(PCSTR format, ...) {
    va_list	args;
    va_start(args, format);
    int len = _vscprintf(format, args);
    if (len > 0) {
        len += (1 + 2);
        PSTR buf = (PSTR) malloc(len);
        if (buf) {
            len = vsprintf_s(buf, len, format, args);
            if (len > 0) {
                while (len && isspace(buf[len-1])) len--;
                buf[len++] = '\r';
                buf[len++] = '\n';
                buf[len] = 0;
                OutputDebugStringA(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}
//
//�򵥵ļ��ܽ����ַ�������
//
void SimpleEncryptString(const char *src,int len,char *dest)
{
    int i;
    for (i = 0; i < len; i++){
        *(dest+i) = *(src+i) + i + 5;
    }
}

void SimpleDecryptString(const char *src,int len,char *dest)
{
    int i;
    for (i = 0; i < len; i++){
        *(dest+i) = *(src+i) - i - 5;
    }
}

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
        DbgPrint("FindResourceA failed : %d\r\n",GetLastError());
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
    OutputDebugStringA("WriteFile ok!\r\n");
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
            OutputDebugStringA( "CreateService() Failed! \r\n" );  
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
        OutputDebugStringA( "CreateService() ok ! \n" );
    }

    //�����������
    bRet = StartService( hServiceDDK, NULL, NULL );  
    if( !bRet ){  
        DWORD dwRtn = GetLastError();  
        if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING ){  
            DbgPrint("StartService() Failed,Err : 0x%x \r\n",dwRtn);
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
//����csrss���
//
BOOL __stdcall SendOpenProcessParameter(HANDLE handle,DWORD ProcessId)
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;
    OPEN_PROCESS_PARAMETER opp  = {0};
    opp.dwCsrssHandle           = (DWORD)handle;
    opp.dwGamePid               = ProcessId;
    DWORD dwRet                 = 0;

    if(MyDeviceIoControl(hDevice,FC_SEND_OPEN_PROCESS_PARAMETER,&opp,sizeof(OPEN_PROCESS_PARAMETER),&opp,sizeof(OPEN_PROCESS_PARAMETER),&dwRet,NULL)){
        CloseHandle(hDevice);
        return true;
    }
    CloseHandle(hDevice);
    return false;
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
    COMMTEST ct                    = {0};
    ct.dwNtOpenProcessIndex        = gZwOpenProcessIndex;
    ct.dwNtReadVirtualMemoryIndex  = gZwReadVirtualMemoryIndex;
    ct.dwNtWriteVirtualMemoryIndex = gZwWriteVirtualMemoryIndex;
    DWORD dwRet                 = 0;
    if(MyDeviceIoControl(hDevice,FC_COMM_TEST,&ct,sizeof(COMMTEST),&ct,sizeof(COMMTEST),&dwRet,NULL)){
        if (ct.success){
            bRet = true;
        }
    }
    CloseHandle(hDevice);
    return bRet;
}

CTMR_API BOOL _cdecl IsDriverLoad()
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;

    DWORD dwRet                 = 0;
    if(MyDeviceIoControl(hDevice,FC_IS_DRIVER_LOAD,NULL,0,NULL,0,&dwRet,NULL)){
        bRet = true;
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
    if (MyDeviceIoControl(hDevice,FC_GET_NAME_BY_ID,pNameInfo,sizeof(NAMEINFO),pNameInfo,sizeof(NAMEINFO),&dwRet,NULL)){
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
    if (MyDeviceIoControl(hDevice,
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
    if (MyDeviceIoControl(hDevice,
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
__declspec(naked) NTSTATUS NTAPI nakedZwDeviceIoControlFile(HANDLE  FileHandle,
    HANDLE           Event,
    PVOID  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength
    )
{
    __asm
    {
        mov     eax, gZwDeviceIoControlFileIndex
        mov     edx, 7FFE0300h
        call    dword ptr [edx]
        retn    28h
    }
}

BOOL __stdcall MyDeviceIoControl(
    HANDLE       hDevice,
    DWORD        dwIoControlCode,
    LPVOID       lpInBuffer,
    DWORD        nInBufferSize,
    LPVOID       lpOutBuffer,
    DWORD        nOutBufferSize,
    LPDWORD      lpBytesReturned,
    LPOVERLAPPED lpOverlapped
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock = {0};
    status = nakedZwDeviceIoControlFile(hDevice,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        dwIoControlCode,
        lpInBuffer,
        nInBufferSize,
        lpOutBuffer,
        nOutBufferSize);
    if (status == STATUS_SUCCESS){
        *lpBytesReturned = ioStatusBlock.Information;
        return true;
    }
    return false;
}

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
    LONG status;
    if (ClientId){
        if (ClientId->UniqueProcess){
            /*ͨ��pid��ȡ��������*/
            NAMEINFO ni = {0};
            ni.dwPid    = (DWORD)ClientId->UniqueProcess;
            if (avGetProcessName(&ni)){
                /*����*/
                char DecryptString[20]={0};
                SimpleDecryptString(GameProcessName,strlen(GameProcessName),DecryptString);
                if (_stricmp(DecryptString,ni.ProcessName) == 0){
                    /*��¼��Ϸpid*/
                    gGamePid = (DWORD)ClientId->UniqueProcess;
                    //*ProcessHandle = (HANDLE)FAKE_HANDLE;
                    //SendOpenProcessParameter((HANDLE)0,gGamePid);
                    //return STATUS_SUCCESS;
                    }
                }
            }
        }
    status = nakedZwOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
    if (status == STATUS_SUCCESS){
        /*��¼��Ϸ���̾��*/
        gGameHandle = *ProcessHandle;
    }
    return status;
}

NTSTATUS NTAPI  avZwReadVirtualMemory(	
    HANDLE 	    ProcessHandle,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToRead,
    PSIZE_T 	NumberOfBytesRead )
{
    char DecryptString[20] = {0};
    if (ProcessHandle == gGameHandle){

        /*���Ҫ��ȡ���ֽڴ��� MAX_BUFFER * 2�Ļ������ܶ�ȡ*/
        if (NumberOfBytesToRead > PAGE_SIZE){
            return STATUS_UNSUCCESSFUL;
        }
        //Ҫ��ȡ��ע���̵��ڴ�
        PREADMEM_INFO pri = new READMEM_INFO;
        if (pri == NULL)
            return STATUS_UNSUCCESSFUL;
        /*����*/
        memset(pri,0,sizeof(READMEM_INFO));
        SimpleDecryptString(GameProcessName,strlen(GameProcessName),DecryptString);
        strcpy_s(pri->ProcessName,MAX_BUFFER_LENGTH,DecryptString);
        pri->BaseAddress         = BaseAddress;
        pri->NumberOfBytesToRead = NumberOfBytesToRead;
        pri->ProcessId           = gGamePid;
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
    char DecryptString[20] = {0};
    if (ProcessHandle == gGameHandle){
        //Ҫд���ע���̵��ڴ�
        /*���Ҫд����ֽڴ��� MAX_BUFFER * 2�Ļ�������д��*/
        if (NumberOfBytesToWrite > PAGE_SIZE){
            return STATUS_UNSUCCESSFUL;
        }
        //Ҫд���ע���̵��ڴ�
        PWRITEMEM_INFO pwi = new WRITEMEM_INFO;
        if (pwi == NULL)
            return STATUS_UNSUCCESSFUL;
        SimpleDecryptString(GameProcessName,strlen(GameProcessName),DecryptString);
        /*����*/
        memset(pwi,0,sizeof(WRITEMEM_INFO));
        strcpy_s(pwi->ProcessName,MAX_BUFFER_LENGTH,DecryptString);
        pwi->BaseAddress          = BaseAddress;
        pwi->NumberOfBytesToWrite = NumberOfBytesToWrite;
        pwi->ProcessId            = gGamePid;
        memcpy_s(pwi->Buffer,PAGE_SIZE,Buffer,NumberOfBytesToWrite);
        if (avWriteMemory(pwi)){
            *NumberOfBytesWritten = pwi->NumberOfBytesWritten;
            delete pwi;
            return STATUS_SUCCESS;
        }
    }
    return nakedZwWriteVirtualMemory(ProcessHandle,BaseAddress,Buffer,NumberOfBytesToWrite,NumberOfBytesWritten);
}
//
//ͨ����������ȡ����id
//
DWORD GetProcessIdByName(wchar_t * wszName)
{
    HANDLE hProcessSnap;
    DWORD dwId  = 0;;
    PROCESSENTRY32W pe32;
    //DWORD dwPriorityClass;
    wchar_t wszProcessName[MAX_PATH]={0};
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if( hProcessSnap == INVALID_HANDLE_VALUE )
        return 0;
    pe32.dwSize = sizeof( PROCESSENTRY32 );
    if( !Process32FirstW( hProcessSnap, &pe32 ) ){
        //printError( TEXT("Process32First") ); // show cause of failure
        CloseHandle( hProcessSnap );          // clean the snapshot object
        return 0;
    }
    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do{
        wcscpy (wszProcessName,pe32.szExeFile);
        //wcscpy_s(wszProcessName,130,pe32.szExeFile);

        if (0 == wcscmp(wszProcessName,wszName)){
            dwId = pe32.th32ProcessID;
            break;
        }

        memset(wszProcessName,0,sizeof(wszProcessName));

    } while( Process32NextW( hProcessSnap, &pe32 ) );

    CloseHandle( hProcessSnap );
    return dwId;
}
//
//��ʼ��CustomReader 
//
CTMR_API BOOL _cdecl InitCustomReader()
{
    BOOL bRet = false;

    /*���ntdll�е���غ�����ԭʼ��ַ*/
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtdll == NULL)
        return false;
    pfnOriZwDeviceIoControlFile = (PFN_ZWDEVICEIOCONTROLFILE)GetProcAddress(hNtdll,"ZwDeviceIoControlFile");
    pfnOriZwOpenProcess         = (PFN_ZWOPENPROCESS)GetProcAddress(hNtdll,"ZwOpenProcess");
    pfnOriZwReadVirtualMemory   = (PFN_ZWREADVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwReadVirtualMemory");
    pfnOriZwWriteVirtualMemory  = (PFN_ZWWRITEVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwWriteVirtualMemory");
    /*��ȡ������*/
    gZwDeviceIoControlFileIndex = *(DWORD *)((DWORD)pfnOriZwDeviceIoControlFile + 1);
    gZwOpenProcessIndex         = *(DWORD *)((DWORD)pfnOriZwOpenProcess + 1);
    gZwReadVirtualMemoryIndex   = *(DWORD *)((DWORD)pfnOriZwReadVirtualMemory + 1);
    gZwWriteVirtualMemoryIndex  = *(DWORD *)((DWORD)pfnOriZwWriteVirtualMemory + 1);
    /*�ͷ�����sys����Դ����ǰĿ¼��*/
    if (!ReleaseResToFile(CTMR_PATH,IDR_SYS1,"SYS")){
        return false;
    }
    OutputDebugStringA("ReleaseResToFile ok!\r\n");
    Sleep(100);
    //��ж������
    UnloadDriver(CTMR_NAME);
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
//     Mhook_SetHook((PVOID*)&pfnOriZwOpenProcess,avZwOpenProcess);
//     Mhook_SetHook((PVOID*)&pfnOriZwReadVirtualMemory,avZwReadVirtualMemory);
//     Mhook_SetHook((PVOID*)&pfnOriZwWriteVirtualMemory,avZwWriteVirtualMemory);


    return bRet;
}

//
//ж��customReader
//
CTMR_API void _cdecl UnloadCustomReader()
{
    UnloadDriver(CTMR_NAME);
//     Mhook_Unhook((PVOID*)&pfnOriZwOpenProcess);
//     Mhook_Unhook((PVOID*)&pfnOriZwReadVirtualMemory);
//     Mhook_Unhook((PVOID*)&pfnOriZwWriteVirtualMemory);
}