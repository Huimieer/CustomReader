#include "Ntos.h"
#include "Tools.h"

extern PDRIVER_OBJECT gMyDriverObject;
/*ԭʼ�ں˵Ļ�ַ*/
ULONG gNtosModuleBase;
BYTE *gReloadModuleBase;
ULONG gNtosModuleSize;

//
//����������SSDT���е�������
//
//ULONG gZwOpenProcessIndex;
//ULONG gZwReadVirtualMemoryIndex;
//ULONG gZwWriteVirtualMemoryIndex;
PFN_KESTACKATTACHPROCESS gReloadKeStackAttackProcess;
PFN_KEUNSTACKDETACHPROCESS gReloadKeUnstackDetachProcess;
PFN_PSLOOKUPPROCESSBYPROCESSID gReloadPsLookupProcessByProcessId;
PFN_NTOPENPROCESS gReloadNtOpenProcess;

PSERVICE_DESCRIPTOR_TABLE ReloadKeServiceDescriptorTable;

/* ����ntosģ�� */
NTSTATUS ReloadNtos()
{
    WCHAR *szNtosFilePath           = NULL;
    PFN_KESTACKATTACHPROCESS pfnKeStackAttackProcess;
    PFN_KEUNSTACKDETACHPROCESS pfnKeUnstackDetachProcess;
    PVOID PsLookupProcessByProcessIdAddr;
    BYTE *NtOpenProcessAddr;

    //PSERVICE_DESCRIPTOR_TABLE pShadowTable = NULL;
    //NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (!GetNtosInfo(&szNtosFilePath,&gNtosModuleBase,&gNtosModuleSize)){
        if (szNtosFilePath)
            ExFreePool(szNtosFilePath);
        return STATUS_UNSUCCESSFUL;
    }
    if (!PeReload(szNtosFilePath,gNtosModuleBase,&gReloadModuleBase,gMyDriverObject)){
        if (szNtosFilePath)
            ExFreePool(szNtosFilePath);
        if (gReloadModuleBase)
            ExFreePool(gReloadModuleBase);
        return STATUS_UNSUCCESSFUL;
    }

    /*��ʼ�������ں˵ķ������������������ض�λ�������滹��ָ��ԭʼ�ں�*/
    ReloadKeServiceDescriptorTable                  = (PSERVICE_DESCRIPTOR_TABLE)((ULONG)KeServiceDescriptorTable-gNtosModuleBase + (ULONG)gReloadModuleBase);
    ReloadKeServiceDescriptorTable->TableSize       = KeServiceDescriptorTable->TableSize;
    ReloadKeServiceDescriptorTable->ServiceTable    = (PULONG)((ULONG)gReloadModuleBase + (ULONG)KeServiceDescriptorTable->ServiceTable - gNtosModuleBase);

    pfnKeStackAttackProcess   = (PFN_KESTACKATTACHPROCESS)GetExportedFunctionAddr(L"KeStackAttachProcess");
    pfnKeUnstackDetachProcess = (PFN_KEUNSTACKDETACHPROCESS)GetExportedFunctionAddr(L"KeUnstackDetachProcess");
    PsLookupProcessByProcessIdAddr = GetExportedFunctionAddr(L"PsLookupProcessByProcessId");
    NtOpenProcessAddr         = GetExportedFunctionAddr(L"NtOpenProcess");
    if (!pfnKeStackAttackProcess || !pfnKeUnstackDetachProcess || !PsLookupProcessByProcessIdAddr || !NtOpenProcessAddr){
        if (szNtosFilePath)
            ExFreePool(szNtosFilePath);
        if (gReloadModuleBase)
            ExFreePool(gReloadModuleBase);
        return STATUS_UNSUCCESSFUL;
    }
    gReloadKeStackAttackProcess   = (PFN_KESTACKATTACHPROCESS)((ULONG)pfnKeStackAttackProcess - gNtosModuleBase + (ULONG)gReloadModuleBase);
    gReloadKeUnstackDetachProcess = (PFN_KEUNSTACKDETACHPROCESS)((ULONG)pfnKeUnstackDetachProcess - gNtosModuleBase + (ULONG)gReloadModuleBase);
    gReloadPsLookupProcessByProcessId = (PFN_PSLOOKUPPROCESSBYPROCESSID)((ULONG)PsLookupProcessByProcessIdAddr - gNtosModuleBase + (ULONG)gReloadModuleBase);
    gReloadNtOpenProcess          = (PFN_NTOPENPROCESS)((ULONG)NtOpenProcessAddr - gNtosModuleBase + (ULONG)gReloadModuleBase);
    if (szNtosFilePath){
        ExFreePool(szNtosFilePath);
    }
    return STATUS_SUCCESS;
}

//
//�ͷ�reloadntos
//
VOID FreeNtos()
{
    if (gReloadModuleBase){
        ExFreePool(gReloadModuleBase);
    }
}
