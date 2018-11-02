//DEXTER - Data EXfiltration TestER
//This file is part of DEXTER Project

//Written by : @maldevel
//Website : https ://www.twelvesec.com/
//GIT : https://github.com/twelvesec/dexter

//TwelveSec(@Twelvesec)

//This program is free software : you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program.If not, see < http://www.gnu.org/licenses/>.

//For more see the file 'LICENSE' for copying permission.

#include "libsysteminfo.h"

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Ws2_32.lib")

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <VersionHelpers.h>

#define SECURITY_WIN32

#pragma comment (lib, "Secur32.lib")
#include <Security.h>

#include <stdio.h>

static bool IsWindowsVersion(unsigned short wMajorVersion, unsigned short wMinorVersion, unsigned short wServicePackMajor, int comparisonType)
{
	if (wMajorVersion < 0 || wMinorVersion < 0 || wServicePackMajor < 0 || comparisonType < 0) return false;

	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, { 0 }, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(VerSetConditionMask(
			0, VER_MAJORVERSION, comparisonType),
			VER_MINORVERSION, comparisonType),
		VER_SERVICEPACKMAJOR, comparisonType);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != false;
}

std::string libsysteminfo::get_computer_name(void) {
	std::string computername = "";
	char *cname;
	DWORD cnameLen = 0;

	if (GetComputerNameExA(ComputerNameNetBIOS, NULL, &cnameLen) == 0 && GetLastError() != ERROR_MORE_DATA) {
		return "";
	}

	if ((cname = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cnameLen)) == NULL) {
		return "";
	}

	if (GetComputerNameExA(ComputerNameNetBIOS, cname, &cnameLen) == 0) {
		HeapFree(GetProcessHeap(), 0, cname);
		cname = NULL;
		return "";
	}

	cname[cnameLen] = 0;

	computername = std::string(cname);
	HeapFree(GetProcessHeap(), 0, cname);
	cname = NULL;

	return computername;
}

std::string libsysteminfo::get_username(void) {
	std::string username = "";
	char *uname;
	DWORD unameLen = 0;

	if (GetUserNameExA(NameSamCompatible, NULL, &unameLen) == 0 && GetLastError() != ERROR_MORE_DATA) {
		return "";
	}

	if ((uname = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, unameLen)) == NULL) {
		return "";
	}

	if (GetUserNameExA(NameSamCompatible, uname, &unameLen) == 0) {
		HeapFree(GetProcessHeap(), 0, uname);
		uname = NULL;
		return "";
	}

	uname[unameLen] = 0;

	username = std::string(uname);
	HeapFree(GetProcessHeap(), 0, uname);
	uname = NULL;

	return username;
}

std::string libsysteminfo::get_os_version(void) {

	if (!IsWindowsServer()) {
		if (IsWindows10OrGreater()) return "Windows_10";
		if (IsWindows8Point1OrGreater()) return "Windows_81";
		if (IsWindows8OrGreater()) return "Windows_8";
		if (IsWindows7SP1OrGreater()) return "Windows_7_SP1";
		if (IsWindows7OrGreater()) return "Windows_7";
		if (IsWindowsVistaSP2OrGreater()) return "Windows_VISTA_SP2";
		if (IsWindowsVistaSP1OrGreater()) return "Windows_VISTA_SP1";
		if (IsWindowsVistaOrGreater()) return "Windows_VISTA";
		if (IsWindowsXPSP3OrGreater()) return "Windows_XP_SP3";
		if (IsWindowsXPSP2OrGreater()) return "Windows_XP_SP2";
		if (IsWindowsXPSP1OrGreater()) return "Windows_XP_SP1";
		if (IsWindowsXPOrGreater())return "Windows_XP";
		return "";
	}
	else {
		if (IsWindowsVersion(HIBYTE(WIN_S03), LOBYTE(WIN_S03), 0, VER_EQUAL)) return "Windows_Server_2003";
		else if (IsWindowsVersion(HIBYTE(WIN_S08), LOBYTE(WIN_S08), 0, VER_EQUAL)) return "Windows_Server_2008";
		else if (IsWindowsVersion(HIBYTE(WIN_S08R2), LOBYTE(WIN_S08R2), 0, VER_EQUAL)) return "Windows_Server_2008_R2";
		else if (IsWindowsVersion(HIBYTE(WIN_S12), LOBYTE(WIN_S12), 0, VER_EQUAL)) return "Windows_Server_2012";
		else if (IsWindowsVersion(HIBYTE(WIN_S12R2), LOBYTE(WIN_S12R2), 0, VER_EQUAL)) return "Windows_Server_2012_R2";
		else if (IsWindowsVersion(HIBYTE(WIN_S16), LOBYTE(WIN_S16), 0, VER_EQUAL)) return "Windows_Server_2016";
		else return "";
	}
}

std::string libsysteminfo::get_active_netface_ip(void) {
	std::string ipaddress = "";
	DWORD size = 0;
	ULONG result = 0;
	PIP_ADAPTER_ADDRESSES aAddr = NULL;
	PIP_ADAPTER_ADDRESSES aAddrIndex = NULL;
	PIP_ADAPTER_UNICAST_ADDRESS aAddrUnicast = NULL;
	WSADATA wsaData;
	WCHAR *buf;
	unsigned long bufSize = 50; //xxx.xxx.xxx.xxx

	if ((result = GetAdaptersAddresses(0, 0, 0, 0, &size)) != ERROR_BUFFER_OVERFLOW) {
		return "";
	}

	if ((aAddr = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)) == NULL) {
		return "";
	}

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, 0, aAddr, &size) != NO_ERROR) {
		HeapFree(GetProcessHeap(), 0, aAddr);
		aAddr = NULL;
		return "";
	}

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		HeapFree(GetProcessHeap(), 0, aAddr);
		aAddr = NULL;
		return "";
	}

	aAddrIndex = aAddr;
	std::wstring tmp;

	while (aAddrIndex) {
		if ((aAddrIndex->IfType == 6 || aAddrIndex->IfType == 71) && aAddrIndex->OperStatus == 1 &&
			std::wstring(aAddrIndex->Description).find(L"Hyper-V") == std::string::npos &&
			std::wstring(aAddrIndex->Description).find(L"VirtualBox") == std::string::npos &&
			std::wstring(aAddrIndex->Description).find(L"VMware") == std::string::npos) {

			if ((aAddrUnicast = aAddrIndex->FirstUnicastAddress) != NULL) {

				if ((buf = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize * sizeof(WCHAR))) == NULL) {
					continue;
				}

				if (WSAAddressToStringW(aAddrUnicast->Address.lpSockaddr,
					aAddrUnicast->Address.iSockaddrLength, NULL, buf, &bufSize) == 0) {
					tmp += std::wstring(buf) + L" ";
					HeapFree(GetProcessHeap(), 0, buf);
					buf = NULL;
				}

			}
		}
		aAddrIndex = aAddrIndex->Next;
	}

	HeapFree(GetProcessHeap(), 0, aAddr);
	aAddr = NULL;

	WSACleanup();

	tmp = tmp.substr(0, tmp.size() - 1);
	ipaddress = std::string(tmp.begin(), tmp.end());
	return ipaddress;
}

std::string libsysteminfo::get_active_netface_mac(void) {
	std::string mac = "";
	DWORD size = 0;
	ULONG result = 0;
	PIP_ADAPTER_ADDRESSES aAddr = NULL;
	PIP_ADAPTER_ADDRESSES aAddrIndex = NULL;
	PIP_ADAPTER_UNICAST_ADDRESS aAddrUnicast = NULL;

	char *buf;
	unsigned long bufSize = 50;

	if ((result = GetAdaptersAddresses(0, 0, 0, 0, &size)) != ERROR_BUFFER_OVERFLOW) {
		return "";
	}

	if ((aAddr = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)) == NULL) {
		return "";
	}

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, 0, aAddr, &size) != NO_ERROR) {
		HeapFree(GetProcessHeap(), 0, aAddr);
		aAddr = NULL;
		return "";
	}

	aAddrIndex = aAddr;

	while (aAddrIndex) {
		if ((aAddrIndex->IfType == 6 || aAddrIndex->IfType == 71) && aAddrIndex->OperStatus == 1 &&
			std::wstring(aAddrIndex->Description).find(L"Hyper-V") == std::string::npos &&
			std::wstring(aAddrIndex->Description).find(L"VirtualBox") == std::string::npos &&
			std::wstring(aAddrIndex->Description).find(L"VMware") == std::string::npos) {

			if ((buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize)) == NULL) {
				continue;
			}

			_snprintf_s(buf, bufSize, _TRUNCATE, "%02X-%02X-%02X-%02X-%02X-%02X", aAddrIndex->PhysicalAddress[0], aAddrIndex->PhysicalAddress[1],
				aAddrIndex->PhysicalAddress[2], aAddrIndex->PhysicalAddress[3], aAddrIndex->PhysicalAddress[4], aAddrIndex->PhysicalAddress[5]);
			mac = std::string(buf);
			HeapFree(GetProcessHeap(), 0, buf);
			buf = NULL;
		}
		aAddrIndex = aAddrIndex->Next;
	}

	HeapFree(GetProcessHeap(), 0, aAddr);
	aAddr = NULL;

	return mac;
}
