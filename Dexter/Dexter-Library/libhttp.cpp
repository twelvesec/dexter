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

#include "libhttp.h"
#include <string>
#include <iostream>

HINTERNET libhttp::open(std::wstring uagent) {
	return InternetOpenW(uagent.c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
}

HINTERNET libhttp::connect(HINTERNET internet, std::wstring host, WORD port) {
	if (internet == NULL)return NULL;

	DWORD ms = 1 * 60 * 1000; //60000ms = 1 minute

	if (InternetSetOptionW(internet, INTERNET_OPTION_CONNECT_TIMEOUT, &ms, sizeof(DWORD)) == FALSE ||
		InternetSetOptionW(internet, INTERNET_OPTION_RECEIVE_TIMEOUT, &ms, sizeof(DWORD)) == FALSE ||
		InternetSetOptionW(internet, INTERNET_OPTION_SEND_TIMEOUT, &ms, sizeof(DWORD)) == FALSE) {
		return NULL;
	}

	return InternetConnectW(internet, host.c_str(), port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
}

HINTERNET libhttp::json_request(HINTERNET connection, std::wstring requestMethod, std::wstring uri, char *data, const WCHAR *headers,
	bool IGNORE_CERT_UNKNOWN_CA, bool IGNORE_CERT_DATE_INVALID, bool HTTPS_CONNECTION) {
	if (connection == NULL)return NULL;

	HINTERNET request;
	const WCHAR *AcceptTypes[] = { L"application/json", NULL };
	DWORD Context = 0;
	DWORD extraFlags = 0, extraFlagsLen = sizeof(extraFlags);
	DWORD status = 0, statusLen = sizeof(status);

	DWORD requestFlags = INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
		INTERNET_FLAG_NO_AUTH | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD;

	if (HTTPS_CONNECTION) {
		requestFlags |= INTERNET_FLAG_SECURE;
	}

	if (IGNORE_CERT_UNKNOWN_CA) {
		requestFlags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
	}

	if (IGNORE_CERT_DATE_INVALID) {
		requestFlags |= INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
	}

	if ((request = HttpOpenRequestW(connection, requestMethod.c_str(), uri.c_str(), DEFAULT_HTTP_VERSION, NULL,
		AcceptTypes, requestFlags, Context)) == NULL) {
		return NULL;
	}

	if (IGNORE_CERT_UNKNOWN_CA) {
		if (!InternetQueryOptionW(request, INTERNET_OPTION_SECURITY_FLAGS, &extraFlags, &extraFlagsLen)) {
			InternetCloseHandle(request);
			request = NULL;
			return NULL;
		}

		extraFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;

		if (!InternetSetOptionW(request, INTERNET_OPTION_SECURITY_FLAGS, &extraFlags, sizeof(extraFlags))) {
			InternetCloseHandle(request);
			request = NULL;
			return NULL;
		}
	}

	if (data == NULL) {
		if (!HttpSendRequestW(request, headers, (DWORD)wcslen(headers), NULL, 0)) {
			//std::cout << GetLastError() << std::endl;

			InternetCloseHandle(request);
			request = NULL;
			return NULL;
		}
	}
	else {
		if (!HttpSendRequestW(request, headers, (DWORD)wcslen(headers), data, (DWORD)strlen(data))) {
			//std::cout << GetLastError() << std::endl;

			InternetCloseHandle(request);
			request = NULL;
			return NULL;
		}
	}

	if (!HttpQueryInfoW(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &statusLen, NULL)) {
		InternetCloseHandle(request);
		request = NULL;
		return NULL;
	}

	if (status != HTTP_STATUS_OK && status != HTTP_STATUS_NOT_FOUND) {
		InternetCloseHandle(request);
		request = NULL;
		return NULL;
	}

	return request;
}

bool libhttp::retrieve_data(HINTERNET request, char **data) {
	if (request == NULL)return false;

	char *downloaded = { 0 };
	DWORD downloadedLen = 0;
	DWORD read = 4096;
	char *tmp;

	if ((downloaded = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, read)) == NULL) {
		return false;
	}

	do {

		if (!InternetReadFile(request, downloaded + downloadedLen, read, &read)) {
			break;
		}

		if (read == 0) {
			*data = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, downloadedLen);
			if (*data == NULL) {
				HeapFree(GetProcessHeap(), 0, downloaded);
				downloaded = NULL;
				return false;
			}

			if (memcpy_s(*data, downloadedLen, downloaded, downloadedLen) != 0) {
				HeapFree(GetProcessHeap(), 0, downloaded);
				downloaded = NULL;
				HeapFree(GetProcessHeap(), 0, *data);
				*data = NULL;
				return false;
			}

			*(*data + downloadedLen) = '\0';

			HeapFree(GetProcessHeap(), 0, downloaded);
			downloaded = NULL;

			return true;
		}

		tmp = (char*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, downloaded, downloadedLen + read);
		if (tmp == NULL) {
			break;
		}

		downloaded = tmp;
		downloadedLen += read;

	} while (1);

	HeapFree(GetProcessHeap(), 0, downloaded);
	downloaded = NULL;

	return false;
}
