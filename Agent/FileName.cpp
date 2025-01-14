#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <tchar.h>
#include <iostream>
using namespace std;

#pragma comment(lib,"wininet.lib")	//InternetSetOption
#pragma comment(lib,"crypt32.lib")	// CertAddEncodedCertificateToStore

#define CA_CERT_FILE _T("ServerCA.pem")
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

int InstallRootCA(LPCTSTR certFilePath, BOOL Wide) //Wide == FALSE(Current User스토어) Wide == True(Local Machine 루트 스토어(관리자 권한 요함)
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
	//파일을 메모리 맵핑
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

	//인증서 스토어 여는 작업
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

	//인증서를 스토어에 추가
	BOOL bRet = CertAddEncodedCertificateToStore(
		hStore, X509_ASN_ENCODING,
		pCertData, fileSize,
		CERT_STORE_ADD_USE_EXISTING,//이미 있는 인증서면 재사용
		NULL
	);
	if (!bRet)
	{
		cout << "CertAdd To Store failed, code : " << GetLastError() << endl;
		CertCloseStore(hStore, 0);
		HeapFree(GetProcessHeap(), 0, pCertData);
		return 6;
	}

	//정리 작업
	CertCloseStore(hStore, 0);
	HeapFree(GetProcessHeap(), 0, pCertData);

	cout << "CA Installed success." << endl;
	return 0;
}

int _tmain()
{
	if (SetProxy(_T("127.0.0.1:8080")) != 0)
		cout << "Failed SetProxy" << endl;
	else
		cout << "Proxy Set Succese" << endl;

	if (InstallRootCA(CA_CERT_FILE, FALSE) != 0)
		cout << "Failed, CA Install" << endl;
	else
		cout << "CA Install Succese" << endl;

	getchar();

	return 0;
}