
// MfcTestee.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CMfcTesteeApp:
// �йش����ʵ�֣������ MfcTestee.cpp
//

class CMfcTesteeApp : public CWinApp
{
public:
	CMfcTesteeApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CMfcTesteeApp theApp;