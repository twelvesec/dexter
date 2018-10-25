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

#include <Windows.h>
#include <VersionHelpers.h>

#define SECURITY_WIN32

#pragma comment (lib, "Secur32.lib")
#include <Security.h>
#include <Lmcons.h>

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
	std::string computername;
	char cname[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD cnameLen = MAX_COMPUTERNAME_LENGTH + 1;

	if (GetComputerNameA(cname, &cnameLen) == TRUE) {
		computername = std::string(cname);
	}

	return computername;
}

std::string libsysteminfo::get_username(void) {
	std::string username = "";
	char uname[UNLEN + 1];
	DWORD unameLen = UNLEN + 1;

	if (GetUserNameExA(NameSamCompatible, uname, &unameLen) == TRUE) {
		username = std::string(uname);
	}

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
		return "Windows";
	}
	else {
		if (IsWindowsVersion(HIBYTE(WIN_S03), LOBYTE(WIN_S03), 0, VER_EQUAL)) return "Windows_Server_2003";
		else if (IsWindowsVersion(HIBYTE(WIN_S08), LOBYTE(WIN_S08), 0, VER_EQUAL)) return "Windows_Server_2008";
		else if (IsWindowsVersion(HIBYTE(WIN_S08R2), LOBYTE(WIN_S08R2), 0, VER_EQUAL)) return "Windows_Server_2008_R2";
		else if (IsWindowsVersion(HIBYTE(WIN_S12), LOBYTE(WIN_S12), 0, VER_EQUAL)) return "Windows_Server_2012";
		else if (IsWindowsVersion(HIBYTE(WIN_S12R2), LOBYTE(WIN_S12R2), 0, VER_EQUAL)) return "Windows_Server_2012_R2";
		else if (IsWindowsVersion(HIBYTE(WIN_S16), LOBYTE(WIN_S16), 0, VER_EQUAL)) return "Windows_Server_2016";
		else return "Windows_Server";
	}
}
