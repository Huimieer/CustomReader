#include "Comm.h"
#include "Tools.h"

#define CommDeviceName			L"\\Device\\ReaderDevice"
#define CommSymLink				L"\\??\\ReaderSymLink"

PFN_KESTACKATTACHPROCESS gReloadKeStackAttachProcess;
PFN_KEUNSTACKDETACHPROCESS gReloadKeUnstackDetachProcess;
//extern ULONG gZwOpenProcessIndex;
//extern ULONG gZwReadVirtualMemoryIndex;
//extern ULONG gZwWriteVirtualMemoryIndex;
NTSTATUS __stdcall MyReadVirtualMemory(	
    char 	    *ProcessName,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToRead,
    PSIZE_T 	NumberOfBytesRead )
{
    NTSTATUS status;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;

    status = LookupProcessByName(ProcessName,&targetProcess);
    if (!NT_SUCCESS(status)){
        return status;
    }
    gReloadKeStackAttachProcess((PKPROCESS)targetProcess,&apcState);
    if (MmIsAddressValidEx(BaseAddress)){
        __try{
            ProbeForRead(BaseAddress,NumberOfBytesToRead,sizeof(BYTE));
            ProbeForWrite(Buffer,NumberOfBytesToRead,sizeof(BYTE));
            RtlCopyMemory(Buffer,BaseAddress,NumberOfBytesToRead);

            ProbeForWrite(NumberOfBytesRead,sizeof(ULONG),sizeof(ULONG));
            *NumberOfBytesRead = NumberOfBytesToRead;
        }
        __except(EXCEPTION_EXECUTE_HANDLER){
            status  = STATUS_UNSUCCESSFUL;
            gReloadKeUnstackDetachProcess(&apcState);
            return status;
        }
    }
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
    NTSTATUS status;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;

    status = LookupProcessByName(ProcessName,&targetProcess);
    if (!NT_SUCCESS(status)){
        return status;
    }
    gReloadKeStackAttachProcess((PKPROCESS)targetProcess,&apcState);
    if (MmIsAddressValidEx(BaseAddress)){
        __try{
            ProbeForRead(Buffer,NumberOfBytesToWrite,sizeof(BYTE));
            ProbeForWrite(BaseAddress,NumberOfBytesToWrite,sizeof(BYTE));
            RtlCopyMemory(BaseAddress,Buffer,NumberOfBytesToWrite);

            ProbeForWrite(NumberOfBytesWritten,sizeof(ULONG),sizeof(ULONG));
            *NumberOfBytesWritten = NumberOfBytesToWrite;
        }
        __except(EXCEPTION_EXECUTE_HANDLER){
            status  = STATUS_UNSUCCESSFUL;
            gReloadKeUnstackDetachProcess(&apcState);
            return status;
        }
    }
    gReloadKeUnstackDetachProcess(&apcState);
    return status;
}

//
//����һ������ͨ�ŵ�Device
//
NTSTATUS CreateCommDevice(IN PDRIVER_OBJECT pDriverObj)
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
	return ntStatus;
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
//�û�������ǲ
//
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
			PCOMMTEST pCommTest         = (PCOMMTEST)pIrp->AssociatedIrp.SystemBuffer;
			pCommTest->success  = TRUE;
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
            __try{
                ProbeForRead(pri,sizeof(READMEM_INFO),sizeof(UCHAR));
            }
            __except(EXCEPTION_EXECUTE_HANDLER){
                status = GetExceptionCode();
            }
            if (NT_SUCCESS(status)){
                status  = MyReadVirtualMemory(pri->ProcessName,
                    pri->BaseAddress,
                    pri->Buffer,
                    pri->NumberOfBytesToRead,
                    &pri->NumberOfBytesRead);
            }
            info = NT_SUCCESS(status) ? cbout : 0;

        }
        break;
    case FC_WRITE_PROCESS_MEMORY:
        {
            PWRITEMEM_INFO pwi  = (PWRITEMEM_INFO)pIrp->AssociatedIrp.SystemBuffer;

            __try{
                ProbeForRead(pwi,sizeof(WRITEMEM_INFO),sizeof(UCHAR));
            }
            __except(EXCEPTION_EXECUTE_HANDLER){
                status = GetExceptionCode();
            }
            if (NT_SUCCESS(status)){
                status  = MyWriteVirtualMemory(pwi->ProcessName,
                    pwi->BaseAddress,
                    pwi->Buffer,
                    pwi->NumberOfBytesToWrite,
                    &pwi->NumberOfBytesWritten);
            }
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
//����R3��R0��ͨ��
//
NTSTATUS SetupComm(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS ntStatus		= STATUS_UNSUCCESSFUL;
	if (pDriverObj == NULL)
		return STATUS_UNSUCCESSFUL;

	ntStatus = CreateCommDevice(pDriverObj);
	if (!NT_SUCCESS(ntStatus)){
		return ntStatus;
	}
	LogPrint("CreateCommDevice ok!\r\n");
	/*�����ɹ���ע����ǲ����*/
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UserCmdDispatcher;

	return STATUS_SUCCESS;
}