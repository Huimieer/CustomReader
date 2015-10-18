#include "HookEngine.h"
#include "xde.h"

/*�ر�д����*/
VOID disableWriteProtect()  
{
    __asm
    {
        cli
            mov eax,cr0
            and eax,not 10000h
            mov cr0,eax
    }
}

/*����д����*/
VOID enableWriteProtect()  
{
    __asm
    {
        mov eax,cr0
            or eax,10000h
            mov cr0,eax
            sti
    }
}

BOOL setInlineHook(PHOOKINFO hookInfo)
{
    BYTE jmpCode[5]         = {0xe9,0x00,0x00,0x00,0x00};
    int copyLength          = 0;//��hook�Ļ��ָ��ĳ��ȣ������ƻ�һ��������ָ��
    int length              = 0;
    struct xde_instr instr  = {0};

    if (!hookInfo)
        return FALSE;
    while (copyLength < 5){
        length = xde_disasm((unsigned char *)(hookInfo->originAddress + copyLength),&instr);
        if (length == 0)
            return FALSE;
        copyLength += length;
    }
    /*copy��ָ��Ȳ�Ҫ����16���ֽ�*/
    if(copyLength > 16)
        return FALSE;

    /*����jmpָ������*/
    *(ULONG*)&jmpCode[1]  = hookInfo->targetAddress - hookInfo->originAddress - 5;

    hookInfo->retAddress  =(PVOID)(hookInfo->originAddress + copyLength);
    hookInfo->patchLength = (USHORT)copyLength;

    disableWriteProtect();
    /*����ԭʼ�ֽڵ�HookZone*/
    RtlCopyMemory(hookInfo->hookZone,(PVOID)hookInfo->originAddress,copyLength);
    RtlFillMemory((PVOID)hookInfo->originAddress,copyLength,0x90);
    RtlCopyMemory((PVOID)hookInfo->originAddress,jmpCode,5);
    enableWriteProtect();
    return TRUE;
}

VOID removeInlineHook(PHOOKINFO hookInfo)
{
    if (hookInfo){
        if (hookInfo->patchLength > 0){
            disableWriteProtect();
            RtlCopyMemory((PVOID)hookInfo->originAddress,hookInfo->hookZone,hookInfo->patchLength);
            enableWriteProtect();
        }
    }
}