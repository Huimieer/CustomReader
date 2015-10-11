#include "Ntos.h"

extern PDRIVER_OBJECT gMyDriverObject;
/*ԭʼ�ں˵Ļ�ַ*/
ULONG gNtosModuleBase;
BYTE *gReloadModuleBase;

extern PFN_KESTACKATTACHPROCESS gReloadKeStackAttachProcess;
extern PFN_KEUNSTACKDETACHPROCESS gReloadKeUnstackDetachProcess;

//
//����������SSDT���е�������
//
//ULONG gZwOpenProcessIndex;
//ULONG gZwReadVirtualMemoryIndex;
//ULONG gZwWriteVirtualMemoryIndex;

/* ����ntosģ�� */
NTSTATUS ReloadNtos()
{
    WCHAR *szNtosFilePath           = NULL;
    ULONG ulNtosModuleSize          = 0;
    BYTE *pKeStackAttachProcess     = NULL;
    BYTE * pKeUnstackDetachProcess  = NULL;
    //PSERVICE_DESCRIPTOR_TABLE pShadowTable = NULL;
    //NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (!GetNtosInfo(&szNtosFilePath,&gNtosModuleBase,&ulNtosModuleSize)){
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
    pKeStackAttachProcess           = GetExportedFunctionAddr(L"KeStackAttachProcess");
    pKeUnstackDetachProcess         = GetExportedFunctionAddr(L"KeUnstackDetachProcess");
    if(!pKeStackAttachProcess || !pKeUnstackDetachProcess){
        if (szNtosFilePath)
            ExFreePool(szNtosFilePath);
        if (gReloadModuleBase)
            ExFreePool(gReloadModuleBase);
        return STATUS_UNSUCCESSFUL;
    }
    /*��ʼ�������л�����*/
    gReloadKeStackAttachProcess     = (PFN_KESTACKATTACHPROCESS)((ULONG)pKeStackAttachProcess - gNtosModuleBase + (ULONG)gReloadModuleBase);
    gReloadKeUnstackDetachProcess   = (PFN_KEUNSTACKDETACHPROCESS)((ULONG)pKeUnstackDetachProcess - gNtosModuleBase + (ULONG)gReloadModuleBase);
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
