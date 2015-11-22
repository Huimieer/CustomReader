#include "ProcessProtect.h"
#include "HookEngine.h"
#include "LogSystem.h"
#include "Tools.h"

HOOKINFO gObReferenceObjectByHandleInfo;
HOOKINFO gObOpenObjectByPointerInfo;
HOOKINFO gNtQueryVirtualMemoryInfo;
PVOID PspCidTable;

extern STRUCT_OFFSET gStructOffset;
extern PEPROCESS ProtectProcess;
extern HANDLE ProtectProcessId;
extern HANDLE CsrssHandle;
extern DWORD GameProcessId;
extern PSERVICE_DESCRIPTOR_TABLE ReloadKeServiceDescriptorTable;

__declspec(naked)VOID ObReferenceObjectByHandleZone()
{
    NOP_PROC;
    __asm jmp [gObReferenceObjectByHandleInfo.retAddress];
}

NTSTATUS
    __stdcall
    NewObReferenceObjectByHandle (
     HANDLE Handle,
     ACCESS_MASK DesiredAccess,
     POBJECT_TYPE ObjectType,
     KPROCESSOR_MODE AccessMode,
     PVOID *Object,
     POBJECT_HANDLE_INFORMATION HandleInformation
    )
{
    NTSTATUS status;
    PEPROCESS GameProcess;
    PEPROCESS tmpProcess;
    POBJECT_HEADER ObjectHeader;
    PFN_OBREFERENCEOBJECTBYHANDLE pfnObReferenceObjectByHandle;
    pfnObReferenceObjectByHandle = (PFN_OBREFERENCEOBJECTBYHANDLE)ObReferenceObjectByHandleZone;


    /*是否是查询内存函数调用*/
    if (PsGetCurrentProcess() == ProtectProcess){
        if (Handle == FAKE_HANDLE){
            if (ObjectType == *PsProcessType){
                status = LookupProcessByProcessId(GameProcessId,&GameProcess);
                if(NT_SUCCESS(status)){

                    ObjectHeader = OBJECT_TO_OBJECT_HEADER(GameProcess);
                    /*手动增加引用计数*/
                    InterlockedIncrement(&ObjectHeader->PointerCount);
                    LogPrint("get process!\r\n");
                    *Object = GameProcess;
                    return status;
                }
            }
        }
    }

    /*不是我的进程在使用则调用原始的函数，也有可能是上面的PsLookup执行失败了*/
    status = pfnObReferenceObjectByHandle(Handle,
        DesiredAccess,
        ObjectType,
        AccessMode,
        Object,
        HandleInformation
        );
    if (!NT_SUCCESS(status)){
        return status;
    }

    if (isGameProcess()){

        if (ObjectType == *PsProcessType){

            if ((PEPROCESS)*Object == ProtectProcess){

                LogPrint("Game Open My Process[2]!\r\n");

                ObDereferenceObject(*Object);

//                 status = LookupProcessByName("Tencentdl.exe",&tmpProcess);
// 
//                 if (NT_SUCCESS(status)){
// 
//                     (PEPROCESS)*Object = tmpProcess;
// 
//                     ObjectHeader = OBJECT_TO_OBJECT_HEADER(tmpProcess);
// 
//                     /*手动增加引用计数*/
//                     InterlockedIncrement(&ObjectHeader->PointerCount);
// 
//                     return status;
//                 }

                return STATUS_UNSUCCESSFUL;
            }
        }
    }
    return status;
}


BOOL HookObReferenceObjectByHandle()
{
    BOOL bRetOk = FALSE;
    ULONG ulObReferenceObjectByHandleAddr;
    ulObReferenceObjectByHandleAddr = (ULONG)GetExportedFunctionAddr(L"ObReferenceObjectByHandle");
    if (ulObReferenceObjectByHandleAddr == 0)
        return FALSE;

    gObReferenceObjectByHandleInfo.originAddress = ulObReferenceObjectByHandleAddr;
    gObReferenceObjectByHandleInfo.targetAddress = (ULONG)NewObReferenceObjectByHandle;
    gObReferenceObjectByHandleInfo.hookZone      = (PVOID)ObReferenceObjectByHandleZone;
    
    bRetOk = setInlineHook(&gObReferenceObjectByHandleInfo);
    if(!bRetOk)
        LogPrint("HookObReferenceObjectByHandle->setInlineHook failed\r\n");
    return bRetOk;
}

VOID UnhookObReferenceObjectByHandle()
{
    removeInlineHook(&gObReferenceObjectByHandleInfo);
}


__declspec(naked)VOID ObOpenObjectByPointerZone()
{
    NOP_PROC;
    __asm jmp [gObOpenObjectByPointerInfo.retAddress];
}
NTSTATUS   __stdcall
NewObOpenObjectByPointer(                          
     PVOID Object,                                 
     ULONG HandleAttributes,                       
     PACCESS_STATE PassedAccessState,              
     ACCESS_MASK DesiredAccess,                    
     POBJECT_TYPE ObjectType,                      
     KPROCESSOR_MODE AccessMode,                   
     PHANDLE Handle                                
    )
{
    NTSTATUS status;
    PFN_OBJOPENOBJECTBYPOINTER pfnObOpenObjectByPointer;
    PEPROCESS tmpProcess;

    pfnObOpenObjectByPointer = (PFN_OBJOPENOBJECTBYPOINTER)ObOpenObjectByPointerZone;

    if(isGameProcess()){

        if (ObjectType == *PsProcessType){

            if ((PEPROCESS)Object == ProtectProcess){

                LogPrint("Game Open My Process![1]\r\n");

                status = LookupProcessByName("Tencentdl.exe",&tmpProcess);

                if (NT_SUCCESS(status)){

                   status = pfnObOpenObjectByPointer(tmpProcess,
                        HandleAttributes,
                        PassedAccessState,
                        DesiredAccess,
                        ObjectType,
                        AccessMode,
                        Handle);

                   return status;
                }
                else{

                    status = LookupProcessByName("TenioDL.exe",&tmpProcess);

                    if (NT_SUCCESS(status)){

                        status = pfnObOpenObjectByPointer(tmpProcess,
                            HandleAttributes,
                            PassedAccessState,
                            DesiredAccess,
                            ObjectType,
                            AccessMode,
                            Handle);

                        return status;
                    }
                }
                //return STATUS_UNSUCCESSFUL;
            }
        }
    }

    return pfnObOpenObjectByPointer(Object,
        HandleAttributes,
        PassedAccessState,
        DesiredAccess,
        ObjectType,
        AccessMode,
        Handle);
}

BOOL HookObOpenObjectByPointer()
{
    BOOL bRetOk = FALSE;
    ULONG ulObOpenObjectByPointerAddr;
    ulObOpenObjectByPointerAddr = (ULONG)GetExportedFunctionAddr(L"ObOpenObjectByPointer");
    if (ulObOpenObjectByPointerAddr == 0)
        return FALSE;

    gObOpenObjectByPointerInfo.originAddress = ulObOpenObjectByPointerAddr;
    gObOpenObjectByPointerInfo.targetAddress = (ULONG)NewObOpenObjectByPointer;
    gObOpenObjectByPointerInfo.hookZone      = (PVOID)ObOpenObjectByPointerZone;

    bRetOk = setInlineHook(&gObOpenObjectByPointerInfo);
    if(!bRetOk)
        LogPrint("HookObOpenObjectByPointer->setInlineHook failed\r\n");
    return bRetOk;
}

VOID UnhookObOpenObjectByPointer()
{
    removeInlineHook(&gObOpenObjectByPointerInfo);
}


__declspec(naked) VOID NtQueryVirtualMemoryZone()
{
    NOP_PROC;
    __asm jmp [gNtQueryVirtualMemoryInfo.retAddress]
}

NTSTATUS __stdcall
    NewNtQueryVirtualMemory(
    __in HANDLE ProcessHandle,
    __in PVOID BaseAddress,
    __in MEMORY_INFORMATION_CLASS MemoryInformationClass,
    __out_bcount(MemoryInformationLength) PVOID MemoryInformation,
    __in SIZE_T MemoryInformationLength,
    __out_opt PSIZE_T ReturnLength
    )
{
    NTSTATUS status;
    PFN_NTQUERYVIRTUALMEMORY pfnOrinNtQueryVirtualMemory = (PFN_NTQUERYVIRTUALMEMORY)NtQueryVirtualMemoryZone;

    status = pfnOrinNtQueryVirtualMemory(ProcessHandle,BaseAddress,MemoryInformationClass,MemoryInformation,MemoryInformationLength,ReturnLength);
    if (!NT_SUCCESS(status)){
        LogPrint("query failed,code: 0x%x\r\n",status);
    }
    else{
        LogPrint("NewNtQueryVirtualMemory ok!\r\n");
    }
    return status;
}

BOOL HookNtQueryVirtualMemory()
{
    ULONG oriNtQueryVirtualMemoryAddr = ReloadKeServiceDescriptorTable->ServiceTable[178];
    gNtQueryVirtualMemoryInfo.originAddress = oriNtQueryVirtualMemoryAddr;
    gNtQueryVirtualMemoryInfo.targetAddress = (ULONG)NewNtQueryVirtualMemory;
    gNtQueryVirtualMemoryInfo.hookZone      = NtQueryVirtualMemoryZone;

    return setInlineHook(&gNtQueryVirtualMemoryInfo);
}

VOID UnhookNtQueryVirtualMemory()
{
    removeInlineHook(&gNtQueryVirtualMemoryInfo);
}


//
//遍历exenumhandletable 回调函数
//
BOOLEAN EnumerateHandleCallBack(
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,//PHANDLE_TABLE_ENTRY
    IN HANDLE Handle,
    IN PVOID EnumParameter
    )
{

    if (ARGUMENT_PRESENT(EnumParameter) && *(HANDLE*)EnumParameter == Handle){

        *(PHANDLE_TABLE_ENTRY *)EnumParameter =  HandleTableEntry;
        //ProcessObject = (HandleTableEntry->Value) & (~7);         //掩去低三位
        return TRUE;
    }
    return FALSE;
}

BOOL RemoveProcessFromHandleTable()
{
    BOOL bRet = FALSE;
    NTSTATUS status;
    PVOID CsrssHandleTable;
    HANDLE CsrssPid;
    PEPROCESS CsrssProcess;
    PVOID EnumPar;
    PFN_EXENUMHANDLETABLE pfnExEnumHandleTable = (PFN_EXENUMHANDLETABLE)GetExportedFunctionAddr(L"ExEnumHandleTable");
    if (!pfnExEnumHandleTable){
        LogPrint("get ExEnumHandleTable addr failed\r\n");
        return FALSE;
    }
    PspCidTable = GetPspCidTableByKpcr();
    if (!PspCidTable){
        LogPrint("GetPspCidTableByKpcr failed\r\n");
        return FALSE;
    }
    
    /*这样写不可靠*/
    status = QueryCsrssPid(&CsrssPid);
    //status = LookupProcessByName("csrss.exe",&CsrssProcess);
    if (!NT_SUCCESS(status)){
        LogPrint("get csrss.exe process failed\r\n");
        return FALSE;
    }

    status = PsLookupProcessByProcessId(CsrssPid,&CsrssProcess);
    if (!NT_SUCCESS(status)){
        return FALSE;
    }
    ObDereferenceObject(CsrssProcess);

    /*获取csrss的handletable*/

    CsrssHandleTable = (PVOID)*(ULONG *)((BYTE *)CsrssProcess + gStructOffset.EProcessObjectTable);
    EnumPar = ProtectProcessId;
    if (pfnExEnumHandleTable(CsrssHandleTable,EnumerateHandleCallBack,&EnumPar,NULL)){

        ULONG FirstFree = *(ULONG *)((ULONG)CsrssHandleTable + gStructOffset.HANDLE_TABLE_FirstFree);
        /*如果成功 EnumPar里面就是handletableentry*/
        InterlockedExchangePointer(&((PHANDLE_TABLE_ENTRY)EnumPar)->Object, NULL);
        ((PHANDLE_TABLE_ENTRY)EnumPar)->GrantedAccess = FirstFree;

        /*pid销毁*/
        *(ULONG *)((ULONG)CsrssHandleTable + gStructOffset.HANDLE_TABLE_FirstFree) = (ULONG)ProtectProcessId;
    }
//     else{
//         return FALSE;
//     }

    EnumPar = ProtectProcessId;
    if (pfnExEnumHandleTable(PspCidTable,EnumerateHandleCallBack,&EnumPar,NULL)){

        ULONG FirstFree = *(ULONG *)((ULONG)PspCidTable + gStructOffset.HANDLE_TABLE_FirstFree);
        /*如果成功 EnumPar里面就是handletableentry*/
        InterlockedExchangePointer(&((PHANDLE_TABLE_ENTRY)EnumPar)->Object, NULL);
        ((PHANDLE_TABLE_ENTRY)EnumPar)->GrantedAccess = FirstFree;

        /*pid销毁*/
        *(ULONG *)((ULONG)PspCidTable + gStructOffset.HANDLE_TABLE_FirstFree) = (ULONG)ProtectProcessId;
    }
    else{
        return FALSE;
    }
    return TRUE;
}
//xp系统
//nt!NtDuplicateObject+0xb2:
//805b4a90 ff75e4      push    dword ptr [ebp-1Ch]
//805b4a93 ff750c          push    dword ptr [ebp+0Ch]
//805b4a96 ff75d8          push    dword ptr [ebp-28h]
//805b4a99 e88cfaffff      call    nt!ObDuplicateObject (805b452a)


//nt!ObDuplicateObject+0x389:
//805b48b3 8b5db4          mov     ebx,dword ptr [ebp-4Ch]
//805b48b6 8d45f0          lea     eax,[ebp-10h]
//805b48b9 50              push    eax
//805b48ba 53              push    ebx
//805b48bb e84a190500      call    nt!ExCreateHandle (8060620a)
//805b48c0 85c0            test    eax,eax
PVOID GetExCreateHandleAddr()
{
    PVOID pNtDuplicateObject;
    PVOID pObDuplicateObject;
    PVOID pExCreateHandleAddr;
    BYTE *pStart;
    int i;
    BOOLEAN bHasFind = FALSE;
    pNtDuplicateObject = GetExportedFunctionAddr(L"NtDuplicateObject");
    if (!pNtDuplicateObject){
        LogPrint("get NtDuplicateObject failed\r\n");
        return NULL;
    }
    pStart = (BYTE *)pNtDuplicateObject;
    for (i = 0; i < 0x100; i++){
        if (*(pStart - 1) == 0xe8  &&
            *(PUSHORT)(pStart - 4) == 0x75ff &&
            *(PUSHORT)(pStart - 7) == 0x75ff){
                pObDuplicateObject = (PVOID)((ULONG)(pStart-1) + *(PULONG)pStart + 5);
                bHasFind = TRUE;
                break;
        }
        pStart++;
    }
    if (!bHasFind){
        return NULL;
    }
    pStart = (BYTE *)((BYTE*)pObDuplicateObject + 0x300);
    for (i = 0; i < 0x100; i++){
        if (*(pStart - 1) == 0xe8 &&
            *(pStart + 4) == 0x85 &&
            *(pStart + 5) == 0xc0){
                pExCreateHandleAddr = (PVOID)((ULONG)(pStart-1) + *(PULONG)pStart + 5);
                bHasFind = TRUE;
                break;
        }
        pStart++;
    }
    if (!bHasFind){
        return NULL;
    }
    return pExCreateHandleAddr;
}

VOID RestoreProcessToHandleTable()
{
    typedef HANDLE
        (__stdcall *PFN_EXCREATEHANDLE) (
         PVOID HandleTable,
         PHANDLE_TABLE_ENTRY HandleTableEntry
        );
    HANDLE_TABLE_ENTRY hte = {0};
    PFN_EXCREATEHANDLE pExCreateHandleAddr;
    HANDLE NewPid;

    pExCreateHandleAddr = (PFN_EXCREATEHANDLE)GetExCreateHandleAddr();
    if (!pExCreateHandleAddr){
        return;
    }

    hte.Object        = ProtectProcess;
    hte.GrantedAccess = 0;
    NewPid = pExCreateHandleAddr(PspCidTable,&hte);
    *(ULONG *)((ULONG)ProtectProcess + gStructOffset.EProcessUniqueProcessId) = (ULONG)NewPid;
}

BOOL StartProcessProtect()
{
    PLIST_ENTRY pActiveList;
    PLIST_ENTRY pHandleTableList;
    PVOID pObjectTable;
    if (!HookObReferenceObjectByHandle())
        return FALSE;
    if (!HookObOpenObjectByPointer()){
        UnhookObReferenceObjectByHandle();
        return FALSE;
    }
    //DbgBreakPoint();
    if (!RemoveProcessFromHandleTable()){
        UnhookObReferenceObjectByHandle();
        UnhookObOpenObjectByPointer();
        return FALSE;
    }

    /*断掉进程链表*/
    pActiveList = (PLIST_ENTRY)((BYTE*)ProtectProcess + gStructOffset.EProcessActiveProcessLinks);
    pActiveList->Flink->Blink = pActiveList->Blink;
    pActiveList->Blink->Flink = pActiveList->Flink;
    pActiveList->Flink        = pActiveList;
    pActiveList->Blink        = pActiveList;


    ///*断掉句柄表链表*/
    pObjectTable = ((BYTE*)ProtectProcess + gStructOffset.EProcessObjectTable);
    pHandleTableList = (PLIST_ENTRY)(*(ULONG*)pObjectTable + gStructOffset.HANDLE_TABLE_HandleTableList);
    pHandleTableList->Flink->Blink = pHandleTableList->Blink;
    pHandleTableList->Blink->Flink = pHandleTableList->Flink;
    pHandleTableList->Flink        = pHandleTableList;
    pHandleTableList->Blink        = pHandleTableList;


    /*修改进程pid*/
    //gProtectProcessId = *(ULONG *)((ULONG)ProtectProcess + gStructOffset.EProcessUniqueProcessId);
    *(ULONG *)((ULONG)ProtectProcess + gStructOffset.EProcessUniqueProcessId) = 4;
    //if (!HookNtQueryVirtualMemory()){
    //    UnhookObReferenceObjectByHandle();
    //    UnhookObOpenObjectByPointer();
    //    return FALSE;
    //}

    return TRUE;
}
VOID StopProcessProtect()
{
    UnhookObReferenceObjectByHandle();
    UnhookObOpenObjectByPointer();

    /*恢复pid*/
    RestoreProcessToHandleTable();
    //UnhookNtQueryVirtualMemory();
}