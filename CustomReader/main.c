//
//  [10/7/2015 13:04:57 vvLinker]
//
#include "LogSystem.h"
#include "Utils.h"
#include "Version.h"
#include "Comm.h"

PDRIVER_OBJECT gMyDriverObject;
//
//����ж�غ���
//
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	LogPrint("DriverUnload called...\r\n");
	DeleteCommDevice(pDriverObj);
}
//
//������ں���
//
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj,PUNICODE_STRING pRegisterPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

    gMyDriverObject = pDriverObj;
	/*ע������ж�غ���*/
	pDriverObj->DriverUnload = DriverUnload;

	DbgBreakPoint();
	/*��ʼ��ϵͳ�汾����ؽṹ��ƫ��Ӳ����*/
	InitStructOffset();

	/*��ʼ��ͨ��*/
	status = SetupComm(pDriverObj);
	if (!NT_SUCCESS(status)){
		return status;
	}

	return STATUS_SUCCESS;
}