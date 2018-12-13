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

#include "libftp.h"

HINTERNET libftp::open(std::wstring uagent) {
	return InternetOpenW(uagent.c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
}

HINTERNET libftp::connect(HINTERNET internet, std::wstring host, WORD port, std::wstring username, std::wstring password) {
	if (internet == NULL)return NULL;

	DWORD ms = 1 * 60 * 1000; //60000ms = 1 minute

	if (InternetSetOptionW(internet, INTERNET_OPTION_CONNECT_TIMEOUT, &ms, sizeof(DWORD)) == FALSE ||
		InternetSetOptionW(internet, INTERNET_OPTION_RECEIVE_TIMEOUT, &ms, sizeof(DWORD)) == FALSE ||
		InternetSetOptionW(internet, INTERNET_OPTION_SEND_TIMEOUT, &ms, sizeof(DWORD)) == FALSE) {
		return NULL;
	}

	return InternetConnectW(internet, host.c_str(), port, username.c_str(), password.c_str(), INTERNET_SERVICE_FTP, 0, 0);
}

bool libftp::set_current_dir(HINTERNET connection, std::wstring directory) {
	if (connection == NULL)return NULL;

	return FtpSetCurrentDirectoryW(connection, directory.c_str());
}

bool libftp::write_file(HINTERNET connection, std::wstring filename, std::string data) {

	HINTERNET file = FtpOpenFileW(connection, filename.c_str(), GENERIC_WRITE, FTP_TRANSFER_TYPE_ASCII, 0);
	if (!file) {
		return false;
	}

	DWORD bytes = 0;

	bool result = InternetWriteFile(file, data.c_str(), data.length(), &bytes);

	InternetCloseHandle(file);
	file = NULL;

	return result;
}
