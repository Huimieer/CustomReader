#include "FileProtect.h"
#include "Tools.h"
#include "HookEngine.h"
#include "LogSystem.h"

HOOKINFO NtCreateFileHookInfo = {0};
WCHAR ProtectDirectory[260]   = {0};
const WCHAR FakeDirectory[260] = L"\\??\\c:\\windows\\system32\\csrss.exe";

PDRIVER_DISPATCH gOriginNtfsCreateDispatch;
PDRIVER_DISPATCH gOriginNtfsReadDispatch;


__declspec(naked) void ZwCreateFileHookZone()
{
    NOP_PROC;
    __asm jmp [NtCreateFileHookInfo.retAddress];
}
/*������*/
NTSTATUS __stdcall 
    NewZwCreateFile(
    __out PHANDLE  FileHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __in_opt PLARGE_INTEGER  AllocationSize,
    __in ULONG  FileAttributes,
    __in ULONG  ShareAccess,
    __in ULONG  CreateDisposition,
    __in ULONG  CreateOptions,
    __in_opt PVOID  EaBuffer,
    __in ULONG  EaLength
    )
{
    NTSTATUS status = STATUS_ACCESS_DENIED;
    UNICODE_STRING uniFakeDir = {0};
    PFN_ZWCREATEFILE pfnZwCreateFile = (PFN_ZWCREATEFILE)ZwCreateFileHookZone;
    if (isGameProcess()){
        //LogPrint("Current Process is GameProcess\r\n");
        /*ͨ�� ObjectAttributes �����ļ�·��*/
        if (ObjectAttributes){
            if (ObjectAttributes->ObjectName){
                /*������·�����жԱ�*/
                if (wcsstr(ObjectAttributes->ObjectName->Buffer,ProtectDirectory)){
//                     RtlInitUnicodeString(&uniFakeDir,FakeDirectory);
//                     RtlZeroMemory(ObjectAttributes->ObjectName->Buffer,ObjectAttributes->Length);
//                     ObjectAttributes->ObjectName->Length = 0;
//                     RtlCopyUnicodeString(ObjectAttributes->ObjectName,&uniFakeDir);

                    LogPrint("GameProcess access my file!\r\n");
                    return STATUS_INVALID_PARAMETER;
                }
            }
        }
    }
    return pfnZwCreateFile(FileHandle,
                            DesiredAccess,
                            ObjectAttributes,
                            IoStatusBlock,
                            AllocationSize,
                            FileAttributes,
                            ShareAccess,
                            CreateDisposition,
                            CreateOptions,
                            EaBuffer,EaLength);
}

//
//
//
BOOL HookNtCreateFile()
{
    BOOL bRetOk = FALSE;

    ULONG ulNtCreateFileAddr;
    ulNtCreateFileAddr = (ULONG)GetExportedFunctionAddr(L"NtCreateFile");

    if(ulNtCreateFileAddr == 0)
        return FALSE;
    /*���ṹ��*/
    NtCreateFileHookInfo.originAddress = ulNtCreateFileAddr;
    NtCreateFileHookInfo.targetAddress = (ULONG)NewZwCreateFile;
    NtCreateFileHookInfo.hookZone      = ZwCreateFileHookZone;

    bRetOk = setInlineHook(&NtCreateFileHookInfo);
    if (!bRetOk)
        LogPrint("HookNtCreateFile failed\r\n");
    return bRetOk;
}


VOID UnhookNtCreateFile()
{

    removeInlineHook(&NtCreateFileHookInfo);

}




//
//Ҫ�滻��ntfs��create����
//
NTSTATUS __stdcall NtfsCreateDispatch(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    //����������
    NTSTATUS status                     = STATUS_UNSUCCESSFUL;
    PIO_STACK_LOCATION IoStackLocation  = NULL;
    PFILE_OBJECT FileObject             = NULL;
    UNICODE_STRING ProtectDir           = {0};

    if (KeGetCurrentIrql() == PASSIVE_LEVEL){
        if (isGameProcess()){
            //���뵽�������֮����Ϊ������Ҫ��ע�ļ�
            IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

            if (!IoStackLocation){
                //���Ǿ�ֱ�ӵ���ԭʼ
                //������Ǹղ�ΪʲôҪ����ԭʼ������ԭ��
                goto _FunctionRet;
            }
            //ȡ������ļ������Ա
            //���ǹ��ĵ���  +0x030 FileName         : _UNICODE_STRING
            FileObject = IoStackLocation->FileObject;
            if (FileObject == NULL){
                //����ļ�����Ϊ�գ���ô���Ǿ�ֱ�ӷ���ԭʼ����
                goto _FunctionRet;
            }
            if (ValidateUnicodeString(&FileObject->FileName)){
                //�����Ƿ�ʱ���ǵ�Ŀ¼
                RtlInitUnicodeString(&ProtectDir,ProtectDirectory);
                if (myRtlStrUnicodeString(&FileObject->FileName,&ProtectDir)){
                    //���� ʧ��
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }
    }
_FunctionRet:
    //����ԭʼ����
    status = gOriginNtfsCreateDispatch(DeviceObject,Irp);
    return status;

}

NTSTATUS __stdcall NtfsReadDispatch(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    //����������
    NTSTATUS status                     = STATUS_UNSUCCESSFUL;
    PIO_STACK_LOCATION IoStackLocation  = NULL;
    PFILE_OBJECT FileObject             = NULL;
    UNICODE_STRING ProtectDir           = {0};

    if (KeGetCurrentIrql() == PASSIVE_LEVEL){
        if (isGameProcess()){
            //���뵽�������֮����Ϊ������Ҫ��ע�ļ�
            IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

            if (!IoStackLocation){
                //���Ǿ�ֱ�ӵ���ԭʼ
                //������Ǹղ�ΪʲôҪ����ԭʼ������ԭ��
                goto _FunctionRet;
            }
            //ȡ������ļ������Ա
            //���ǹ��ĵ���  +0x030 FileName         : _UNICODE_STRING
            FileObject = IoStackLocation->FileObject;
            if (FileObject == NULL){
                //����ļ�����Ϊ�գ���ô���Ǿ�ֱ�ӷ���ԭʼ����
                goto _FunctionRet;
            }
            if (ValidateUnicodeString(&FileObject->FileName)){
                //�����Ƿ�ʱ���ǵ�Ŀ¼
                RtlInitUnicodeString(&ProtectDir,ProtectDirectory);
                if (myRtlStrUnicodeString(&FileObject->FileName,&ProtectDir)){
                    //���� ʧ��
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }
    }
_FunctionRet:
    //����ԭʼ����
    status = gOriginNtfsReadDispatch(DeviceObject,Irp);
    return status;

}

BOOL HookNtfsCreateRead()
{
    NTSTATUS status;
    UNICODE_STRING uniNtfsName = {0};
    PDRIVER_OBJECT NtfsDriverObject;

    RtlInitUnicodeString(&uniNtfsName,L"\\FileSystem\\Ntfs");
    status = ObReferenceObjectByName(&uniNtfsName,
        OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
        		NULL,
		0,
		*IoDriverObjectType, //�������ָ��DriverObject
		KernelMode,				//�ں�ģʽ
		NULL,
		(PVOID*)&NtfsDriverObject);
    if (!NT_SUCCESS(status)){
        LogPrint("HookNtfsCreate->ObReferenceObjectByName failed,status:0x%x\r\n",status);
        return FALSE;
    }

    /*�滻create����*/
    gOriginNtfsCreateDispatch = NtfsDriverObject->MajorFunction[IRP_MJ_CREATE];
    gOriginNtfsReadDispatch   = NtfsDriverObject->MajorFunction[IRP_MJ_READ];
    NtfsDriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)NtfsCreateDispatch;
    NtfsDriverObject->MajorFunction[IRP_MJ_READ]   = (PDRIVER_DISPATCH)NtfsReadDispatch;
    ObDereferenceObject(NtfsDriverObject);
    return TRUE;
}


VOID RestoreNtfsCreateRead()
{
    NTSTATUS status;
    UNICODE_STRING uniNtfsName = {0};
    PDRIVER_OBJECT NtfsDriverObject;

    RtlInitUnicodeString(&uniNtfsName,L"\\FileSystem\\Ntfs");
    status = ObReferenceObjectByName(&uniNtfsName,
        OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
        NULL,
        0,
        *IoDriverObjectType, //�������ָ��DriverObject
        KernelMode,				//�ں�ģʽ
        NULL,
        (PVOID*)&NtfsDriverObject);
    if (!NT_SUCCESS(status)){
        LogPrint("RestoreNtfsCreate->ObReferenceObjectByName failed,status:0x%x\r\n",status);
        return;
    }

    /*�ָ�ԭʼ����*/
    NtfsDriverObject->MajorFunction[IRP_MJ_CREATE] = gOriginNtfsCreateDispatch;
    NtfsDriverObject->MajorFunction[IRP_MJ_READ]   = gOriginNtfsReadDispatch;
    ObDereferenceObject(NtfsDriverObject);
}

/*������Ŀ¼�ڵ��ļ��������ʣ��ڵ�ǰ�����»���������*/
BOOL startFileProtect()
{
    BOOL isOk                 = FALSE;
    WCHAR dosPath[MAX_PATH]   = {0};
    WCHAR tmpDir[MAX_PATH]    = {0};
    UNICODE_STRING uniDosPath = {0};
    if (!getCurrentProcessFullDosPath(dosPath))
        return FALSE;
    LogPrint("Current dos path is %ws\r\n",dosPath);
    RtlInitUnicodeString(&uniDosPath,dosPath);
    if (!getCurrentProcessDirectory(&uniDosPath,tmpDir)){
        LogPrint("getCurrentProcessFullPath failed\r\n");
        return FALSE;
    }
    
    /*ȥ���̷� ���� c: �����ַ�*/
    //wcscpy(ProtectDirectory,&tmpDir[0]+2);
    wcscpy(ProtectDirectory,&tmpDir[0]);
    LogPrint("ProtectDirectory: %ws\r\n",ProtectDirectory);
    
    /*hook fsd create*/
    isOk = HookNtCreateFile();
    if (!isOk)
        LogPrint("HookNtCreateFile failed...\r\n");
    return isOk;
}

VOID stopFileProtect()
{
    UnhookNtCreateFile();
}