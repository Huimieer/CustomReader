#include "Ntos.h"

extern PDRIVER_OBJECT gMyDriverObject;

/* ����ntosģ�� */
NTSTATUS ReloadNtos(PDRIVER_OBJECT   DriverObject)
{
    //PSERVICE_DESCRIPTOR_TABLE pShadowTable = NULL;
    //NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (!GetNtosInformation(&SystemKernelFilePath,&SystemKernelModuleBase,&SystemKernelModuleSize)){
        if (SystemKernelFilePath){
            ExFreePool(SystemKernelFilePath);
        }
        return STATUS_UNSUCCESSFUL;
    }
    if (!PeReload(SystemKernelFilePath,SystemKernelModuleBase,&ReloadNtosImageBase,gMyDriverObject)){
        if (SystemKernelFilePath){
            ExFreePool(SystemKernelFilePath);
        }
        if (ReloadNtosImageBase){
            ExFreePool(ReloadNtosImageBase);
        }
        return STATUS_UNSUCCESSFUL;
    }
    ReloadServiceTable = GetOriginServiceTableFromReloadModule(SystemKernelModuleBase,(ULONG)ReloadNtosImageBase);

    /* ReloadShadowServiceTable ֻ������copyǰ7���ֽڵ����ǵĺ�����ȥ */
    //g_pOriginShadowTable =(PSERVICE_DESCRIPTOR_TABLE)ExAllocatePool(NonPagedPool,sizeof(SERVICE_DESCRIPTOR_TABLE));
    //if (g_pOriginShadowTable)
    //{
    //	RtlZeroMemory((PVOID)g_pOriginShadowTable,sizeof(SERVICE_DESCRIPTOR_TABLE));
    //	if (pShadowTable)
    //	{
    //		g_pOriginShadowTable->TableSize = pShadowTable[1].TableSize;
    //		g_pOriginShadowTable->ArgumentTable = pShadowTable[1].ArgumentTable;
    //		g_pOriginShadowTable->CounterTable = pShadowTable[1].CounterTable;
    //		g_pOriginShadowTable->ServiceTable = pShadowTable[1].ServiceTable;
    //	}
    //}
    //���������ں�·�������ͷŲ��Ƿ��أ�
    if (SystemKernelFilePath){
        ExFreePool(SystemKernelFilePath);
    }
    //ntos�ض�λ֮��reloadģ���е�ssdt����Ļ���ԭʼ�� 

    return STATUS_SUCCESS;
}
