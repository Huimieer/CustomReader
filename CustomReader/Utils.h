#ifndef _UTILS_H_
#define _UTILS_H_

#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#define  MAX_PATH 260

typedef unsigned char  BOOL, *PBOOL;
typedef unsigned char  BYTE, *PBYTE;
typedef unsigned long  DWORD, *PDWORD;
typedef unsigned short WORD, *PWORD;

typedef unsigned int    UINT;

typedef struct _AUX_ACCESS_DATA {
    PPRIVILEGE_SET PrivilegesUsed;
    GENERIC_MAPPING GenericMapping;
    ACCESS_MASK AccessesToAudit;
    ACCESS_MASK MaximumAuditMask;
    //ULONG Unknown[41];
} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        };
        struct {
            PVOID LoadedImports;
        };
    };
    PVOID EntryPointActivationContext;

    PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION  // ϵͳģ����Ϣ
{
    ULONG  Reserved[2];  
    ULONG  Base;        
    ULONG  Size;         
    ULONG  Flags;        
    USHORT Index;       
    USHORT Unknown;     
    USHORT LoadCount;   
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];   
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _tagSysModuleList {          //ģ�����ṹ
    ULONG ulCount;
    SYSTEM_MODULE_INFORMATION smi[1];
} MODULES, *PMODULES;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
	/*
	* Table containing cServices elements of pointers to service handler
	* functions, indexed by service ID.
	*/
	PULONG   ServiceTable;
	/*
	* Table that counts how many times each service is used. This table
	* is only updated in checked builds.
	*/
	PULONG  CounterTable;
	/*
	* Number of services contained in this table.
	*/
	ULONG   TableSize;
	/*
	* Table containing the number of bytes of parameters the handler
	* function takes.
	*/
	PUCHAR  ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;
/*����ϵͳ������*/
extern PSERVICE_DESCRIPTOR_TABLE    KeServiceDescriptorTable;

typedef struct _KAPC_STATE             // 5 elements, 0x18 bytes (sizeof) 
{                                                                         
    /*0x000*/     struct _LIST_ENTRY ApcListHead[2];                                    
    /*0x010*/     PVOID   Process;                                            
    /*0x014*/     UINT8   KernelApcInProgress;                                     
    /*0x015*/     UINT8   KernelApcPending;                                        
    /*0x016*/     UINT8   UserApcPending;                                                                               
}KAPC_STATE, *PKAPC_STATE; 

PCHAR PsGetProcessImageFileName(PEPROCESS Eprocess);

NTKERNELAPI				
    NTSTATUS
    ObCreateObject(
    IN KPROCESSOR_MODE ProbeMode,
    IN POBJECT_TYPE ObjectType,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN KPROCESSOR_MODE OwnershipMode,
    IN OUT PVOID ParseContext OPTIONAL,
    IN ULONG ObjectBodySize,
    IN ULONG PagedPoolCharge,
    IN ULONG NonPagedPoolCharge,
    OUT PVOID *Object
    );

NTKERNELAPI
    NTSTATUS
    SeCreateAccessState(
    PACCESS_STATE AccessState,
    PAUX_ACCESS_DATA AuxData,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping
    );

NTKERNELAPI                                                     
    NTSTATUS                                                        
    ObReferenceObjectByHandle(                                      
    IN HANDLE Handle,                                           
    IN ACCESS_MASK DesiredAccess,                               
    IN POBJECT_TYPE ObjectType OPTIONAL,                        
    IN KPROCESSOR_MODE AccessMode,                              
    OUT PVOID *Object,                                          
    OUT POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL   
    );                                                          
NTKERNELAPI                                                     
    NTSTATUS                                                        
    ObOpenObjectByPointer(                                          
    IN PVOID Object,                                            
    IN ULONG HandleAttributes,                                  
    IN PACCESS_STATE PassedAccessState OPTIONAL,                
    IN ACCESS_MASK DesiredAccess OPTIONAL,                      
    IN POBJECT_TYPE ObjectType OPTIONAL,                        
    IN KPROCESSOR_MODE AccessMode,                              
    OUT PHANDLE Handle                                          
    ); 

NTSTATUS __stdcall ZwQuerySystemInformation(

    IN ULONG SystemInformationClass,

    PVOID SystemInformation,

    ULONG SystemInformationLength,

    PULONG ReturnLength
    );
extern POBJECT_TYPE *IoDriverObjectType;
NTSTATUS __stdcall
    ObReferenceObjectByName(
    IN PUNICODE_STRING ObjectName,
    IN ULONG Attributes,
    IN PACCESS_STATE PassedAccessState OPTIONAL,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN POBJECT_TYPE ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN OUT PVOID ParseContext OPTIONAL,
    OUT PVOID *Object
    );

typedef NTSTATUS (NTAPI *PFN_PSLOOKUPPROCESSBYPROCESSID)(
    HANDLE    ProcessId,
    PEPROCESS *Process
    );


NTSTATUS NTAPI PsLookupProcessByProcessId(
      HANDLE    ProcessId,
     PEPROCESS *Process
    );

//VOID NTAPI KeStackAttachProcess	(IN PKPROCESS 	Process,OUT PKAPC_STATE 	ApcState );	
//VOID NTAPI KeUnstackDetachProcess(IN PKAPC_STATE ApcState)	;

typedef VOID (NTAPI *PFN_KESTACKATTACHPROCESS)(IN PKPROCESS 	Process,OUT PKAPC_STATE 	ApcState );	
typedef VOID (NTAPI *PFN_KEUNSTACKDETACHPROCESS)(IN PKAPC_STATE ApcState)	;

typedef NTSTATUS (NTAPI *PFN_MMCOPYVIRTUALMEMORY)(
    IN PEPROCESS FromProcess,
    IN CONST VOID *FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
    );
typedef NTSTATUS (__stdcall *PFN_NTOPENPROCESS)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
    );
typedef NTSTATUS (__stdcall *PFN_NTREADVIRTUALMEMORY)(
    __in HANDLE ProcessHandle,
    __in_opt PVOID BaseAddress,
    __out_bcount(BufferSize) PVOID Buffer,
    __in SIZE_T BufferSize,
    __out_opt PSIZE_T NumberOfBytesRead
    );

typedef NTSTATUS (__stdcall *PFN_NTWRITEVIRTUALMEMORY) (
    __in HANDLE ProcessHandle,
    __in_opt PVOID BaseAddress,
    __in_bcount(BufferSize) CONST VOID *Buffer,
    __in SIZE_T BufferSize,
    __out_opt PSIZE_T NumberOfBytesWritten
    );
typedef struct _OBJECT_CREATE_INFORMATION {
    ULONG Attributes;
    HANDLE RootDirectory;
    PVOID ParseContext;
    KPROCESSOR_MODE ProbeMode;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG SecurityDescriptorCharge;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQos;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION;

// begin_ntosp
typedef struct _OBJECT_CREATE_INFORMATION *POBJECT_CREATE_INFORMATION;;

typedef struct _OBJECT_HEADER {
    LONG_PTR PointerCount;
    union {
        LONG_PTR HandleCount;
        PVOID NextToFree;
    };
    POBJECT_TYPE Type;
    UCHAR NameInfoOffset;
    UCHAR HandleInfoOffset;
    UCHAR QuotaInfoOffset;
    UCHAR Flags;

    union {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };

    PSECURITY_DESCRIPTOR SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

#define OBJECT_TO_OBJECT_HEADER( o ) \
    CONTAINING_RECORD( (o), OBJECT_HEADER, Body )

typedef enum _MEMORY_INFORMATION_CLASS { 
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS (__stdcall
    *PFN_NTQUERYVIRTUALMEMORY)(
    __in HANDLE ProcessHandle,
    __in PVOID BaseAddress,
    __in MEMORY_INFORMATION_CLASS MemoryInformationClass,
    __out_bcount(MemoryInformationLength) PVOID MemoryInformation,
    __in SIZE_T MemoryInformationLength,
    __out_opt PSIZE_T ReturnLength
    );
#endif//_UTILS_H_