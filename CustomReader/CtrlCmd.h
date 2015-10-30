#pragma once

//
//��׼��IO������
//
#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
	)
#define  CTRL_BASE 0xa00	// ����0x800
#define CTRL_EXPRESSION(i)   CTL_CODE(FILE_DEVICE_UNKNOWN,(CTRL_BASE+i),METHOD_BUFFERED,FILE_ANY_ACCESS)
//�ж��ǲ��ǿ�����
//#define CTRL_SUCCESS(code) (((code) &  0x88880000) == 0x88880000)

//
//����һϵ�п����룬����R3��R0ͨ��
//
#define FC_COMM_TEST		        CTRL_EXPRESSION(0)			//����ͨ��
#define FC_WRITE_PROCESS_MEMORY     CTRL_EXPRESSION(1)          //д�����ڴ�����
#define FC_READ_PROCESS_MEMORY      CTRL_EXPRESSION(2)          //�������ڴ�����

#define FC_GET_NAME_BY_ID           CTRL_EXPRESSION(3)          //

//
//�ж��ǲ���α���
//
#define  IS_MY_HANDLE(x)            ((((DWORD)(x)) & 0xc0000000) == 0xc0000000) // 1100 0000...
//
//��PID������ҵľ��
//
#define  PID_TO_MY_HANDLE(x)        (HANDLE)((x) | 0xc0000000)

//
//α�����pidת��
//
#define MY_HANDLE_TO_PID(x)         (DWORD)(((DWORD)(x)) & ~0xc0000000)
