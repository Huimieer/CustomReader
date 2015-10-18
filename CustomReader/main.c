//
//  [10/7/2015 13:04:57 vvLinker]
//
#include "LogSystem.h"
#include "Utils.h"
#include "Tools.h"
#include "Version.h"
#include "Ntos.h"
#include "CtrlCmd.h"
#include "CommStruct.h"
#include "FileProtect.h"


#define CommDeviceName			L"\\Device\\ReaderDevice"
#define CommSymLink				L"\\??\\ReaderSymLink"


PDRIVER_OBJECT gMyDriverObject;

PFN_KESTACKATTACHPROCESS gReloadKeStackAttachProcess;
PFN_KEUNSTACKDETACHPROCESS gReloadKeUnstackDetachProcess;

NTSTATUS __stdcall MyReadVirtualMemory(	
    char 	    *ProcessName,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToRead,
    PSIZE_T 	NumberOfBytesRead )
{
    NTSTATUS status         = STATUS_UNSUCCESSFUL;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;

    status = LookupProcessByName(ProcessName,&targetProcess);
    if (!NT_SUCCESS(status)){
        return status;
    }
    gReloadKeStackAttachProcess((PKPROCESS)targetProcess,&apcState);
    RtlCopyMemory(Buffer,BaseAddress,NumberOfBytesToRead);

    *NumberOfBytesRead = NumberOfBytesToRead;
    gReloadKeUnstackDetachProcess(&apcState);
    return status;
}

NTSTATUS __stdcall MyWriteVirtualMemory(
    char 	    *ProcessName,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToWrite,
    PSIZE_T 	NumberOfBytesWritten )
{
    NTSTATUS status         = STATUS_UNSUCCESSFUL;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;

    status = LookupProcessByName(ProcessName,&targetProcess);
    if (!NT_SUCCESS(status)){
        return status;
    }
    gReloadKeStackAttachProcess((PKPROCESS)targetProcess,&apcState);

    RtlCopyMemory(BaseAddress,Buffer,NumberOfBytesToWrite);
    *NumberOfBytesWritten = NumberOfBytesToWrite;

    gReloadKeUnstackDetachProcess(&apcState);
    return status;
}

//
//ɾ��device
//
VOID DeleteComm(IN PDRIVER_OBJECT pDriverObj)
{
    PDEVICE_OBJECT		pDevObj			= NULL;
    UNICODE_STRING		uniSymLinkName	= {0};

    pDevObj = pDriverObj->DeviceObject;
    if (pDevObj != NULL){
        /*ɾ����������*/
        RtlInitUnicodeString(&uniSymLinkName,CommSymLink);
        IoDeleteSymbolicLink(&uniSymLinkName);

        /*ɾ���豸*/
        IoDeleteDevice(pDevObj);
        pDevObj = NULL;
        LogPrint("DeleteCommDevice ok!\r\n");
    }

}

//
//����R3��R0��ͨ��
//
NTSTATUS SetupComm(PDRIVER_OBJECT pDriverObj)
{
    NTSTATUS			ntStatus		= STATUS_UNSUCCESSFUL;	
    UNICODE_STRING		uniDeviceName	= {0};
    UNICODE_STRING		uniSymLinkName	= {0};
    PDEVICE_OBJECT		pDevObj			= NULL;

    /*�����豸*/
    RtlInitUnicodeString(&uniDeviceName,CommDeviceName);
    ntStatus = IoCreateDevice(pDriverObj,
        0,
        &uniDeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        TRUE,
        &pDevObj);
    if (!NT_SUCCESS(ntStatus)){
        LogPrint("IoCreateDevice failed...\r\n");
        return ntStatus;
    }
    /*�����豸*/
    pDevObj->Flags |= DO_BUFFERED_IO;

    /*������������*/
    RtlInitUnicodeString(&uniSymLinkName,CommSymLink);
    ntStatus = IoCreateSymbolicLink(&uniSymLinkName,&uniDeviceName);
    if(!NT_SUCCESS(ntStatus)){
        LogPrint("IoCreateSymbolicLink failed...\r\n");
        IoDeleteDevice(pDevObj);
        return ntStatus;
    }
    LogPrint("CreateCommDevice ok!\r\n");
    /*�����ɹ���ע����ǲ����*/
    return STATUS_SUCCESS;
}

//
//����ж�غ���
//
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	LogPrint("DriverUnload called...\r\n");
	DeleteComm(pDriverObj);
    stopFileProtect();
    FreeNtos();
}
//
//ͨ�õ���ǲ
//

NTSTATUS CommDispatcher (IN PDEVICE_OBJECT DeviceObject,IN PIRP pIrp)
{

    pIrp->IoStatus.Status       = STATUS_SUCCESS;
    pIrp->IoStatus.Information  = 0;
    IoCompleteRequest(pIrp,IO_NO_INCREMENT);
    return STATUS_SUCCESS;

}
NTSTATUS UserCmdDispatcher (IN PDEVICE_OBJECT DeviceObject,IN PIRP pIrp)
{
    NTSTATUS status				= STATUS_SUCCESS;
    PIO_STACK_LOCATION stack	= NULL;
    ULONG cbin					= 0;
    ULONG cbout					= 0;
    ULONG cmd					= 0;
    ULONG info					= 0;
    stack	= IoGetCurrentIrpStackLocation(pIrp);
    /*���뻺������С*/
    cbin    = stack->Parameters.DeviceIoControl.InputBufferLength;
    /*�����������С*/
    cbout   = stack->Parameters.DeviceIoControl.OutputBufferLength;
    //�õ�������
    cmd		= stack->Parameters.DeviceIoControl.IoControlCode;
    switch(cmd){
    case FC_COMM_TEST:
        {
            PCOMMTEST pCommTest = (PCOMMTEST)pIrp->AssociatedIrp.SystemBuffer;
            pCommTest->success  = TRUE;
            /*�����￪���ļ�����*/
            startFileProtect();
            info = cbout;
        }
        break;
    case FC_GET_NAME_BY_ID:
        {
            PNAMEINFO pni       = (PNAMEINFO)pIrp->AssociatedIrp.SystemBuffer;
            status              = LookupNameByProcessId(pni->dwPid,pni->ProcessName);
            if (NT_SUCCESS(status))
                info = cbout;
            else
                info = 0;
        }
        break;
    case FC_READ_PROCESS_MEMORY:
        {
            PREADMEM_INFO pri   = (PREADMEM_INFO)pIrp->AssociatedIrp.SystemBuffer;

            status  = MyReadVirtualMemory(pri->ProcessName,
                pri->BaseAddress,
                pri->Buffer,
                pri->NumberOfBytesToRead,
                &pri->NumberOfBytesRead);
            info = (status == STATUS_SUCCESS) ? cbout : 0;
        }
        break;
    case FC_WRITE_PROCESS_MEMORY:
        {
            PWRITEMEM_INFO pwi  = (PWRITEMEM_INFO)pIrp->AssociatedIrp.SystemBuffer;
                status  = MyWriteVirtualMemory(pwi->ProcessName,
                    pwi->BaseAddress,
                    pwi->Buffer,
                    pwi->NumberOfBytesToWrite,
                    &pwi->NumberOfBytesWritten);
            info = NT_SUCCESS(status) ? cbout : 0;
    }
        break;
    default:
        status  = STATUS_INVALID_VARIANT;
        break;
    }
    /*����irp���״̬*/
    pIrp->IoStatus.Status      = status;
    /*����irp����Ĳ�����*/
    pIrp->IoStatus.Information = info;
    //����irp����
    IoCompleteRequest(pIrp,IO_NO_INCREMENT);
    return status;
}
//
//������ں���
//
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj,PUNICODE_STRING pRegisterPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

    gMyDriverObject = pDriverObj;
	/*ע������ж�غ���*/
	pDriverObj->DriverUnload                            = DriverUnload;
    pDriverObj->MajorFunction[IRP_MJ_CREATE]            = CommDispatcher;
    pDriverObj->MajorFunction[IRP_MJ_CLOSE]             = CommDispatcher;
    pDriverObj->MajorFunction[IRP_MJ_READ]              = CommDispatcher;
    pDriverObj->MajorFunction[IRP_MJ_WRITE]             = CommDispatcher;
    pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]    = UserCmdDispatcher;

	DbgBreakPoint();
	/*��ʼ��ϵͳ�汾����ؽṹ��ƫ��Ӳ����*/
	InitStructOffset();

	/*��ʼ��ͨ��*/
    status = SetupComm(pDriverObj);
    if (!NT_SUCCESS(status)){
        return status;
    }

    /*����Ntos*/
    status = ReloadNtos();
    if(!NT_SUCCESS(status)){
        DeleteComm(pDriverObj);
        return status;
    }

	return STATUS_SUCCESS;
}