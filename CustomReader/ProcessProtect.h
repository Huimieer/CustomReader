#pragma once
#include "Utils.h"
#include "CtrlCmd.h"


/*�ٵľ��ֵ*/
#define FAKE_HANDLE         (0x87654321)
//
//���������APIȥ���ڴ棬�Ǿ�һ����Ҫһ�������������ObReferenceHandleByPointer hook�������һ�£�
//
typedef NTSTATUS
    (__stdcall *PFN_OBREFERENCEOBJECTBYHANDLE) (
     HANDLE Handle,
     ACCESS_MASK DesiredAccess,
     POBJECT_TYPE ObjectType,
     KPROCESSOR_MODE AccessMode,
     PVOID *Object,
     POBJECT_HANDLE_INFORMATION HandleInformation
    );

typedef NTSTATUS                                                        // ntifs
    (__stdcall *PFN_OBJOPENOBJECTBYPOINTER)(                                          // ntifs
     PVOID Object,                                            // ntifs
     ULONG HandleAttributes,                                  // ntifs
     PACCESS_STATE PassedAccessState,                // ntifs
     ACCESS_MASK DesiredAccess,                      // ntifs
     POBJECT_TYPE ObjectType,                        // ntifs
     KPROCESSOR_MODE AccessMode,                              // ntifs
     PHANDLE Handle                                          // ntifs
    );  
// ntifs


BOOL StartProcessProtect();
VOID StopProcessProtect();