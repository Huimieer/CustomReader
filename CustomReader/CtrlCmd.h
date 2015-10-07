#pragma once

//
//��׼��IO������
//
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