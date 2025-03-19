#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <tchar.h>
#include <iostream>
#include "resource.h"
using namespace std;

#pragma comment(lib,"wininet.lib")	//InternetSetOption
#pragma comment(lib,"crypt32.lib")	// CertAddEncodedCertificateToStore

#define CA_CERT_FILE _T("ServerCA.pem")
#define INTERNET_SETTINGS \
    _T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
#define RUN_SETTINGS \
	_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run")

#define WM_TRAYICON		WM_USER+1

int SetProxy(LPCTSTR IpPort,BOOL Check = TRUE)
{
	HKEY hKey;
	DWORD Type = 0, Size = sizeof(DWORD);
	static DWORD OldValue = 0;
	LONG lResult = RegOpenKeyEx(HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);
	try
	{
		if (lResult != ERROR_SUCCESS)
			throw 1;

		if (Check == TRUE)
		{
			lResult = RegQueryValueEx(hKey, _T("ProxyEnable"), NULL, &Type, (BYTE*)&OldValue, &Size);
			DWORD enable = 1;
			lResult = RegSetValueEx(hKey, _T("ProxyEnable"), 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
			if (lResult != ERROR_SUCCESS)
				throw lResult;

			lResult = RegSetValueEx(hKey, _T("ProxyServer"), 0, REG_SZ, (BYTE*)IpPort, (DWORD)((_tcslen(IpPort) + 1) * sizeof(TCHAR)));
			if (lResult != ERROR_SUCCESS)
				throw lResult;
		}
		else
		{
			lResult = RegSetValueEx(hKey, _T("ProxyEnable"), 0, REG_DWORD, (BYTE*)&OldValue, sizeof(OldValue));
			if (lResult != ERROR_SUCCESS)
				throw lResult;
		}
	}
	catch (int lErr)
	{
		MessageBox(NULL, _T("SetProxError"), _T("����"), MB_ICONERROR);
		if (lErr == 1)
			return lErr;
		RegCloseKey(hKey);
		return lErr;
	}

	RegCloseKey(hKey);

	// �ý��ۿ� ������ �뺸��
	InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, 0);

	return 0;
}

int InstallRootCA(LPCTSTR certFilePath, BOOL Wide) //Wide == FALSE(Current User�����) Wide == True(Local Machine ��Ʈ �����(������ ���� ����)
{
	HANDLE hFile = CreateFile(certFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD fileSize = 0, bytesRead;
	BYTE* pCertData = NULL;
	HCERTSTORE hStore = NULL;
	BOOL bRet = FALSE;
	try
	{
		if (hFile == INVALID_HANDLE_VALUE)
			throw 1;

		fileSize = GetFileSize(hFile, NULL);
		if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
			throw 2;
		//������ �޸� ����
		pCertData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);
		if (!pCertData)
			throw 3;

		if (!ReadFile(hFile, pCertData, fileSize, &bytesRead, NULL) || (bytesRead != fileSize))
			throw 4;

		CloseHandle(hFile);

		//������ ����� ���� �۾�
		hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, (Wide ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER)
			| CERT_STORE_OPEN_EXISTING_FLAG
			| CERT_STORE_READONLY_FLAG, _T("ROOT")
		);
		if (!hStore)
			throw 5;

		//�������� ���� �߰�
		bRet = CertAddEncodedCertificateToStore(
			hStore, X509_ASN_ENCODING,
			pCertData, fileSize,
			CERT_STORE_ADD_USE_EXISTING,//�̹� �ִ� �������� ����
			NULL
		);
		if (!bRet)
			throw 6;

		//���� �۾�
		CertCloseStore(hStore, 0);
		HeapFree(GetProcessHeap(), 0, pCertData);
	}
	catch (int lErr)
	{
		if (lErr >= 2 && lErr <= 4)
		{
			if (lErr == 4)
				HeapFree(GetProcessHeap(), 0, pCertData);
			CloseHandle(hFile);
		}
		else if (lErr == 5 || lErr == 6)
		{
			if (lErr == 6)
				CertCloseStore(hStore, 0);
			HeapFree(GetProcessHeap(), 0, pCertData);
		}
		MessageBox(NULL, _T("������ ��ġ ����"), _T("����"), MB_ICONERROR);
		return 1;
	}
	return 0;
}

DWORD WINAPI RegistryWatch(LPVOID lpParam)
{
	HKEY hKey;
	
	LONG lResult = RegOpenKeyEx(HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, KEY_NOTIFY | KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
	if (lResult != ERROR_SUCCESS)
		return 1;

	while (true)
	{
		lResult = RegNotifyChangeKeyValue(hKey, FALSE, REG_NOTIFY_CHANGE_LAST_SET, NULL, FALSE);
		if (lResult != ERROR_SUCCESS)
			break;
		else
		{
			DWORD dwType = 0, dwEnable = 0, dwSize = sizeof(dwEnable);
			if (RegQueryValueEx(hKey, _T("ProxyEnable"), NULL, &dwType, (BYTE*)&dwEnable, &dwSize) == ERROR_SUCCESS)
			{
				if (dwEnable == 0)
				{
					MessageBox(NULL, _T("���Ͻ� ���� ���� ����"), _T("���"), MB_OK | MB_ICONWARNING);
					dwEnable = 1;
					RegSetValueEx(hKey, _T("ProxyEnable"), 0, REG_DWORD, (BYTE*)&dwEnable, sizeof(dwEnable));

					InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
					InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
				}
			}
		}
	}
	RegCloseKey(hKey);
	return 0;
}

int RunTimeStart()
{
	HKEY hKey;
	TCHAR Path[MAX_PATH];
	LONG lResult = RegCreateKeyEx(HKEY_CURRENT_USER, RUN_SETTINGS, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &hKey, NULL);
	if (lResult != ERROR_SUCCESS)
		return 1;
	lResult = RegQueryValueEx(hKey, _T("AGENT"), NULL, NULL, NULL, NULL);
	if (lResult == ERROR_FILE_NOT_FOUND)
	{
		GetModuleFileName(NULL, Path, MAX_PATH);
		lResult = RegSetValueEx(hKey, _T("AGENT"), 0, REG_SZ, (LPBYTE)Path, (DWORD)((_tcslen(Path) + 1) * sizeof(TCHAR)));
	}

	RegCloseKey(hKey);
	return 0;
}

int CheckReg()
{
	HKEY hKey;
	LONG lResult = RegCreateKeyEx(HKEY_CURRENT_USER, RUN_SETTINGS, 0, NULL, NULL, KEY_READ, NULL, &hKey, NULL);
	if (lResult != ERROR_SUCCESS)
		return 1;
	lResult = RegQueryValueEx(hKey, _T("AGENT"), NULL, NULL, NULL, NULL);
	if (lResult == ERROR_FILE_NOT_FOUND)
	{
		RegCloseKey(hKey);
		return 2;
	}
	RegCloseKey(hKey);
	return 0;
}

void DeleteRunTimeSet()
{
	HKEY hKey;
	LONG lResult = RegOpenKeyEx(HKEY_CURRENT_USER, RUN_SETTINGS, 0, KEY_SET_VALUE, &hKey);
	if (lResult != ERROR_SUCCESS)
	{
		MessageBox(NULL, _T("������Ʈ�� ���� ����"), _T("����"), MB_ICONERROR);
		return;
	}
	lResult = RegQueryValue(hKey, _T("AGENT"), NULL, NULL);
	RegDeleteValue(hKey, _T("AGENT"));
	RegCloseKey(hKey);
}

//int LOGIN(LPTSTR ID, LPTSTR PS)
//{
//
//}

#define MAX_LAN		256
//BOOL LogInProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
//{
//	switch (Msg)
//	{
//	case WM_COMMAND:
//		switch (LOWORD(wParam))
//		{
//		case IDOK:
//		{
//			TCHAR ID[256], PS[256];
//			UINT CHResult = GetDlgItemText(hDlg, IDC_EDIT1, ID, sizeof(ID));
//			if (CHResult == 0)
//			{
//				MessageBox(hDlg, _T("���� ���̵� �Դϴ�."), _T("����"), MB_ICONERROR);
//				return FALSE;
//			}
//			CHResult = GetDlgItemText(hDlg, IDC_EDIT2, PS, sizeof(PS));
//			if (CHResult == 0)
//			{
//				MessageBox(hDlg, _T("��й�ȣ�� Ʋ�Ƚ��ϴ�."), _T("����"), MB_ICONERROR);
//				return FALSE;
//			}
//			EndDialog(hDlg, IDOK);
//			return TRUE;
//		}
//		case IDCANCEL:
//			EndDialog(hDlg, IDCANCEL);
//			return TRUE;
//		}
//	}
//	return FALSE;
//}

struct HWORK
{
	HANDLE hWork;
	DWORD dwThrId;
};
HWORK hw;
NOTIFYICONDATA g_nid{ 0 };

BOOL DlgProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
		case WM_INITDIALOG:
			hw.hWork = CreateThread(NULL, 0, RegistryWatch, &hw, CREATE_SUSPENDED, &hw.dwThrId);
			//RegChgNoti�Լ��� ���Ӽ� �����带 �ʿ���� => �����tp�� ���Ӽ��� ������ �����ϴ� ������� �����캼��
			//�ش� ���α׷��� ������Ǯ ������ �ʿ���ٰ� �Ǵ� ����� ���� ���� �����带 ����� �����ص� ����(�񵿱� �ƴϹǷ�)
			if (CheckReg() == 0)
			{
				HWND hc = GetDlgItem(hDlg, IDC_CHECK3);
				SendMessage(hc, BM_SETCHECK, BST_CHECKED, NULL);
				SetProxy(_T("127.0.0.1:8080"));
				ResumeThread(hw.hWork);
			}
			break;
		case WM_COMMAND:
			switch (LOWORD(wParam))
			{
				case IDOK:
				{
					HWND hc1 = GetDlgItem(hDlg, IDC_CHECK1);	//���Ͻ� ����
					if (SendMessage(hc1, BM_GETCHECK, 0, 0) == BST_CHECKED)
					{
						if (InstallRootCA(CA_CERT_FILE, FALSE) != 0)
						{
							SendMessage(hc1, BM_SETCHECK, BST_UNCHECKED, 0);
							return FALSE;
						}
						if (SetProxy(_T("127.0.0.1:8080")) != 0)
							return FALSE;
					}
					HWND hc3 = GetDlgItem(hDlg, IDC_CHECK3);	//����� ���� �� �ǽð� ����
					if (SendMessage(hc3, BM_GETCHECK, 0, 0) == BST_CHECKED)
					{
						RunTimeStart();
						SetProxy(_T("127.0.0.1:8080"));
						ResumeThread(hw.hWork);
					}

					MessageBeep(1);
					MessageBox(hDlg, _T("���� �Ϸ�"), _T("����"), MB_OK);
					SendMessage(hc1, BM_SETCHECK, BST_UNCHECKED, 0);
					return TRUE;
				}
				break;
				case IDCANCEL:
				{
					g_nid.cbSize = sizeof(NOTIFYICONDATA);
					g_nid.hWnd = hDlg;
					g_nid.uID = 1;	//�������� ID(���� ����)
					g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
					g_nid.uCallbackMessage = WM_TRAYICON;	//Ʈ���� ������ ���� �޽��� ó��
					g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);	//�ý��� �⺻ ������ ���
					_tcscpy(g_nid.szTip, _T("���Ͻ� ���α׷�"));
					Shell_NotifyIcon(NIM_ADD, &g_nid);	//Ʈ���� ������ ���

					ShowWindow(hDlg, SW_HIDE);	//â ����
					return TRUE;
				}
				break;
			}
			break;
		case WM_TRAYICON:
			if (lParam == WM_LBUTTONDBLCLK)	//���� ����Ŭ�� �� ����
			{
				ShowWindow(hDlg, SW_SHOW);
				SetForegroundWindow(hDlg);
				// ���� �� �� �̻� �ʿ�����Ƿ� Ʈ���� ������ ����
				Shell_NotifyIcon(NIM_DELETE, &g_nid);
			}
			break;
		case WM_CLOSE:
		{
			HWND hc = GetDlgItem(hDlg, IDC_CHECK2);
			if (SendMessage(hc, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{
				SetProxy(_T("127.0.0.1:8080"), FALSE);
				DeleteRunTimeSet();
			}
			//������ ���� ����
			Shell_NotifyIcon(NIM_DELETE, &g_nid);
			CloseHandle(hw.hWork);
			EndDialog(hDlg, IDCANCEL);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
	//INT_PTR Check = DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG1), HWND_DESKTOP, (DLGPROC)LogInProc);
	//if (Check == IDOK)
	//{
	//	DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG2), HWND_DESKTOP, (DLGPROC)DlgProc);
	//}
	DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG2), HWND_DESKTOP, (DLGPROC)DlgProc);
	return 0;
}