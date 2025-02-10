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
	if (lResult != ERROR_SUCCESS)
	{
		cout << "RegOpenKeyEx Error : " << GetLastError() << endl;
		return 1;
	}

	if (Check == TRUE)
	{
		lResult = RegQueryValueEx(hKey, _T("ProxyEnable"), NULL, &Type, (BYTE*)&OldValue, &Size);
		DWORD enable = 1;
		lResult = RegSetValueEx(hKey, _T("ProxyEnable"), 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
		if (lResult != ERROR_SUCCESS)
		{
			cout << "RegSetValueEx Enable Error : " << GetLastError() << endl;
			RegCloseKey(hKey);
			return 2;
		}

		lResult = RegSetValueEx(hKey, _T("ProxyServer"), 0, REG_SZ, (BYTE*)IpPort, (DWORD)((_tcslen(IpPort) + 1) * sizeof(TCHAR)));
		if (lResult != ERROR_SUCCESS)
		{
			cout << "RegSetValueEx IpPortInsert Error : " << GetLastError() << endl;
			RegCloseKey(hKey);
			return 3;
		}
	}
	else
	{
		lResult = RegSetValueEx(hKey, _T("ProxyEnable"), 0, REG_DWORD, (BYTE*)&OldValue, sizeof(OldValue));
		if (lResult != ERROR_SUCCESS)
		{
			cout << "RegSetValueEx Enable Error : " << GetLastError() << endl;
			RegCloseKey(hKey);
			return 2;
		}
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
	if (hFile == INVALID_HANDLE_VALUE)
	{
		cout << "File Open Fail, Code : " << GetLastError() << endl;
		return 1;
	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
	{
		cout << "File size = %d" << fileSize << endl;
		CloseHandle(hFile);
		return 2;
	}
	//������ �޸� ����
	BYTE* pCertData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);
	if (!pCertData)
	{
		cout << "File memory map faile, code : " << GetLastError() << endl;
		CloseHandle(hFile);
		return 3;
	}

	DWORD bytesRead;
	if (!ReadFile(hFile, pCertData, fileSize, &bytesRead, NULL) || (bytesRead != fileSize))
	{
		cout << "File Read faile, code : " << GetLastError() << endl;
		HeapFree(GetProcessHeap(), 0, pCertData);
		CloseHandle(hFile);
		return 4;
	}

	CloseHandle(hFile);

	//������ ����� ���� �۾�
	HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, (Wide ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER)
		| CERT_STORE_OPEN_EXISTING_FLAG
		| CERT_STORE_READONLY_FLAG, _T("ROOT")
	);

	if (!hStore)
	{
		cout << "CertOpenStore failed. \n" << endl;
		HeapFree(GetProcessHeap(), 0, pCertData);
		return 5;
	}

	//�������� ���� �߰�
	BOOL bRet = CertAddEncodedCertificateToStore(
		hStore, X509_ASN_ENCODING,
		pCertData, fileSize,
		CERT_STORE_ADD_USE_EXISTING,//�̹� �ִ� �������� ����
		NULL
	);
	if (!bRet)
	{
		cout << "CertAdd To Store failed, code : " << GetLastError() << endl;
		CertCloseStore(hStore, 0);
		HeapFree(GetProcessHeap(), 0, pCertData);
		return 6;
	}

	//���� �۾�
	CertCloseStore(hStore, 0);
	HeapFree(GetProcessHeap(), 0, pCertData);

	cout << "CA Installed success." << endl;
	return 0;
}

DWORD WINAPI RegistryWatch(LPVOID lpParam)
{
	HKEY hKey;
	HANDLE hEvent;
	
	LONG lResult = RegOpenKeyEx(HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, KEY_NOTIFY | KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
	if (lResult != ERROR_SUCCESS)
		return 1;

	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!hEvent)
	{
		RegCloseKey(hKey);
		return 2;
	}

	while (true)
	{
		lResult = RegNotifyChangeKeyValue(hKey, FALSE, REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE);
		if (lResult != ERROR_SUCCESS)
			break;

		DWORD dwWait = WaitForSingleObject(hEvent, INFINITE);
		if (dwWait == WAIT_OBJECT_0)
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

	CloseHandle(hEvent);
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
BOOL LogInProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDOK:
		{
			TCHAR ID[256], PS[256];
			UINT CHResult = GetDlgItemText(hDlg, IDC_EDIT1, ID, sizeof(ID));
			if (CHResult == 0)
			{
				MessageBox(hDlg, _T("���� ���̵� �Դϴ�."), _T("����"), MB_ICONERROR);
				return FALSE;
			}
			CHResult = GetDlgItemText(hDlg, IDC_EDIT2, PS, sizeof(PS));
			if (CHResult == 0)
			{
				MessageBox(hDlg, _T("��й�ȣ�� Ʋ�Ƚ��ϴ�."), _T("����"), MB_ICONERROR);
				return FALSE;
			}
			EndDialog(hDlg, IDOK);
			return TRUE;
		}
		case IDCANCEL:
			EndDialog(hDlg, IDCANCEL);
			return TRUE;
		}
	}
	return FALSE;
}

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
						if (SetProxy(_T("127.0.0.1:8080")) != 0)
							return FALSE;
						InstallRootCA(CA_CERT_FILE, FALSE);
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
	}
	return FALSE;
}

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
	INT_PTR Check = DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG1), HWND_DESKTOP, (DLGPROC)LogInProc);
	if (Check == IDOK)
	{
		DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG2), HWND_DESKTOP, (DLGPROC)DlgProc);
	}
	return 0;
}