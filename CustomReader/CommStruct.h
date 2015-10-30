#pragma once

#define  MAX_BUFFER_LENGTH      260
#define  PAGE_SIZE (0x1000)
//typedef unsigned char  BOOL, *PBOOL;
//
//ͨ����ؽṹ
//
#pragma pack(push)
#pragma pack(1)
typedef struct tagCOMMTEST{

    DWORD success;//�ṹ�����澡����Ҫʹ�� boolֵ
    DWORD dwZwQueryVirtualMemoryIndex;
}COMMTEST,*PCOMMTEST;

typedef struct tagNAMEINFO{
    DWORD dwPid;
    char ProcessName[MAX_BUFFER_LENGTH];
}NAMEINFO,*PNAMEINFO;

//
//���ڴ溯����Ҫ����Ϣ
//
//HANDLE 	    ProcessHandle,
//PVOID 	    BaseAddress,
//PVOID 	    Buffer,
//SIZE_T 	    NumberOfBytesToRead,
//PSIZE_T 	NumberOfBytesRead
typedef struct tagREADMEM_INFO{
    char   ProcessName[MAX_BUFFER_LENGTH];
    UCHAR  Buffer[PAGE_SIZE];
    PVOID  BaseAddress;
    DWORD  NumberOfBytesToRead;
    DWORD  NumberOfBytesRead;
    DWORD  ProcessId;
}READMEM_INFO,*PREADMEM_INFO;

/*д�ڴ溯����Ҫ����Ϣ*/
    //HANDLE 	    ProcessHandle,
    //PVOID 	    BaseAddress,
    //PVOID 	    Buffer,
    //SIZE_T 	    NumberOfBytesToWrite,
    //PSIZE_T 	NumberOfBytesWritten
typedef struct tagWRITEMEM_INFO{
    char   ProcessName[MAX_BUFFER_LENGTH];
    UCHAR  Buffer[MAX_BUFFER_LENGTH * 2];
    PVOID  BaseAddress;
    DWORD  NumberOfBytesToWrite;
    DWORD  NumberOfBytesWritten;
    DWORD  ProcessId;
}WRITEMEM_INFO,*PWRITEMEM_INFO;

//
//r3 �� 40 ���ͽ��̾��
//
typedef struct tagOPEN_PROCESS_PARAMETER{
    DWORD dwCsrssHandle;
    DWORD dwGamePid;
}OPEN_PROCESS_PARAMETER,*POPEN_PROCESS_PARAMETER;
#pragma pack(pop)
//#pragma pack()