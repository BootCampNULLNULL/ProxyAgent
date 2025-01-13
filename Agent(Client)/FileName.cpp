#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <tchar.h>
#include <iostream>
using namespace std;

#pragma comment(lib,"wininet.lib")	//InternetSetOption
#pragma comment(lib,"crypt32.lib")	// CertAddEncodedCertificateToStore

#define INTERNET_SETTINGS \
    TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")

int SetProxy(LPCTSTR IpPort)
{
	HKEY hKey;
	
	LONG lResult = RegOpenKeyEx(HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, KEY_SET_VALUE, &hKey);
	if (lResult != ERROR_SUCCESS)
	{
		cout << "RegOpenKeyEx Error : " << GetLastError() << endl;
		return 1;
	}

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

	RegCloseKey(hKey);

	// 시스템에 변경을 통보함
	InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, 0);

	return 0;
}

int _tmain()
{
	if (SetProxy(_T("127.0.0.1:8080")) != 0)
		cout << "Failed SetProxy" << endl;
	else
		cout << "Proxy Set Succese" << endl;

	getchar();

	return 0;
}