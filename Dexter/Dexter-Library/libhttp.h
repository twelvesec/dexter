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

#pragma once

#include <Windows.h>
#include <string>
#pragma comment (lib, "wininet.lib")
#include <WinInet.h>

#define DEFAULT_HTTP_VERSION	L"HTTP/1.1"

namespace libhttp {
	HINTERNET open(std::wstring uagent);
	HINTERNET connect(HINTERNET internet, std::wstring host, WORD port);
	HINTERNET json_request(HINTERNET connection, std::wstring requestMethod, std::wstring uri, char *data, const WCHAR *headers,
		bool IGNORE_CERT_UNKNOWN_CA, bool IGNORE_CERT_DATE_INVALID, bool HTTPS_CONNECTION);
	bool retrieve_data(HINTERNET request, char **data);
}
