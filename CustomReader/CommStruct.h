#pragma once

#define  MAX_BUFFER_LENGTH      260
//typedef unsigned char  BOOL, *PBOOL;
//
//ͨ����ؽṹ
//
//#pragma pack(push)
#pragma pack(1)
typedef struct tagCOMMTEST{

    //ULONG ZwOpenProcessIndex;
    //ULONG ZwReadVirtualMemoryIndex;
    //ULONG ZwWriteVirtualMemoryIndex;
    BOOL success;
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
    UCHAR  Buffer[MAX_BUFFER_LENGTH * 2];
    PVOID  BaseAddress;
    DWORD  NumberOfBytesToRead;
    DWORD  NumberOfBytesRead;
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
}WRITEMEM_INFO,*PWRITEMEM_INFO;
//#pragma pack(pop)
#pragma pack()