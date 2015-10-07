#include "Comm.h"

#define CommDeviceName			L"\\Device\\ReaderDevice"
#define CommSymLink				L"\\??\\ReaderSymLink"
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
VOID DeleteCommDevice(IN PDRIVER_OBJECT pDriverObj)
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
			PCOMMTEST pCommTest = (PCOMMTEST)pIrp->AssociatedIrp.SystemBuffer;
			pCommTest->success  = TRUE;
			info = cbout;
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