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

#include "libgit.h"
#include "libreporter.h"
#include "libhttp.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "helper.h"
#include "libcrypt.h"
#include "libencode.h"
#include "libcurl.h"
#include "libmime.h"
#include "libftp.h"
#include "libtcp.h"
#include "libnet.h"

#include <iostream>
#include <string>
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")

static std::wstring pick_random_useragent(std::set<std::wstring> uagents, std::wstring Protocol) {

	std::wstring useragent = helper::pick_random_useragent_fromfile(uagents);
	std::wcout << L"[DEXTER][" << Protocol << L"][User-Agent] " << useragent << std::endl;

	return useragent;
}

static void handle_data(std::string data, std::string password, std::wstring Protocol) {

	std::string tosearch = "%2b";
	std::string replace = "+";
	size_t pos = data.find(tosearch);
	while (pos != std::string::npos)
	{
		data.replace(pos, tosearch.size(), replace);
		pos = data.find(tosearch);
	}

	std::string decrypted_data = libcrypt::decrypt(password, data);
	std::vector<std::string> details;

	details = helper::split_string(decrypted_data.c_str(), '\n');
	if (details.size() > 0) {
		std::wcout << "[DEXTER][" << Protocol << "]" << "[PACKET] ";
		for (int i = 0; i < details.size(); i++) {
			if (i == details.size() - 1) {
				std::cout << details[i];
			}
			else {
				std::cout << details[i] << ", ";
			}
		}
		std::cout << std::endl;
	}
}

static bool check_tcp_server_connectivity(std::wstring protocol, std::wstring host, WORD port) {

	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Checking server connectivity (" << host << ", " << port << ")" << std::endl;

	if (libnet::is_ipv4_or_ipv6_address(host)) {
		if (!libnet::check_tcp_port_connectivity(host, port)) {
			std::wcout << L"[DEXTER][" << protocol << L"] " << L"Unable to contact server (" << helper::GetLastErrorStringW(libnet::LastError) << ")" << std::endl;
			return false;
		}
	}
	else {
		if (!libnet::check_tcp_port_connectivity_byname(host, port)) {
			std::wcout << L"[DEXTER][" << protocol << L"] " << L"Unable to contact server (" << helper::GetLastErrorStringW(libnet::LastError) << ")" << std::endl;
			return false;
		}
	}

	return true;
}

void libreporter::test_http_protocol(std::wstring host, WORD port, std::wstring token_uri_method, std::wstring clients_uri_method, std::wstring tokenuri,
	std::wstring clients_uri, std::set<std::wstring> uagents, WORD clientid, std::string secret, std::string username,
	std::string password, std::string aespassword, std::string PoC_KEYWORD, bool IGNORE_CERT_UNKNOWN_CA, bool IGNORE_CERT_DATE_INVALID,
	bool TLS_CONNECTION) {

	char *downloaded = 0;
	HINTERNET internet = NULL, connection = NULL, request = NULL;
	const WCHAR *token_headers = L"Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n";
	bool result = false;

	std::wstring protocol = (TLS_CONNECTION ? L"HTTPS" : L"HTTP");

	if (!check_tcp_server_connectivity(protocol, host, port)) {
		return;
	}

	std::wstring useragent = helper::pick_random_useragent_fromfile(uagents);
	std::wcout << L"[DEXTER][" << protocol << L"][User-Agent] " << useragent << std::endl;

	std::string token_data = "grant_type=password&client_id=" + std::to_string(clientid) + "&client_secret=" +
		secret + "&username=" + username + "&password=" + password + "&scope=*";

	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Connecting to " << protocol << L" server" << std::endl;

	internet = libhttp::open(useragent);

	if (internet != NULL) {
		connection = libhttp::connect(internet, host, port);
	}

	if (!TLS_CONNECTION) {
		std::wcout << "[DEXTER][" << protocol << "][WARNING] " << "Transmitting unencrypted data over HTTP" << std::endl;
	}

	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Requesting API token with " << protocol << L" packet" << std::endl;

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
		std::wstring clients_headers = L"Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nAuthorization: Bearer " +
			access_token + L"\r\nConnection: close\r\n";

		std::wcout << L"[DEXTER][" << protocol << L"] " << L"Sending data with " << protocol << L" packet" << std::endl;

		if (connection != NULL) {
			request = libhttp::json_request(connection, clients_uri_method, clients_uri, NULL,
				clients_headers.c_str(), IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, TLS_CONNECTION);
		}

		if (request != NULL) {
			result = libhttp::retrieve_data(request, &downloaded);
		}

		if (result && downloaded != NULL) {
			rapidjson::Document clients_response;
			clients_response.Parse(downloaded);

			if (helper::read_bool_value(&clients_response, "success") == true) {

				std::wcout << L"[DEXTER][" << protocol << L"] " << L"Transmission succeeded" << std::endl;

				if (clients_response.HasMember("data") && clients_response["data"].IsArray()) {
					const rapidjson::Value& a = clients_response["data"].GetArray();
					for (rapidjson::SizeType i = 0; i < a.Size(); i++) {
						if (a[i].IsObject()) {
							for (rapidjson::Value::ConstMemberIterator itr = a[i].MemberBegin(); itr != a[i].MemberEnd(); ++itr) {
								if (itr->name != NULL) {
									std::string val(itr->name.GetString());
									if (val == "data" && itr->value != NULL) {
										handle_data(itr->value.GetString(), aespassword, protocol);
									}
								}
							}
						}
					}
				}

			}
			else {

				std::wcout << "[DEXTER][" << protocol << "] " << "Transmission failed" << std::endl;
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

void libreporter::test_gmail_protocol(std::wstring host, WORD port, std::wstring gmail_imap, std::string gmail_imap_inbox_obj, std::string gmail_username,
	std::string gmail_password, std::string gmail_name, std::set<std::wstring> uagents, std::string aespassword, std::string PoC_KEYWORD) {

	int total = 0;
	int i = 0;
	MimeMessage *m = 0;
	std::vector<int> ids;

	libcurl::init();

	std::wstring protocol = L"GMAIL";

	if (!check_tcp_server_connectivity(protocol, host, port)) {
		return;
	}

	std::wstring useragent = pick_random_useragent(uagents, protocol);

	std::wcout << "[DEXTER][" << protocol << "] " << "Connecting to " << protocol << " SMTP server" << std::endl;

	std::wcout << "[DEXTER][" << protocol << "] " << "Sending data with " << protocol << " packet" << std::endl;

	std::string uagent(useragent.begin(), useragent.end());

	std::wcout << "[DEXTER][" << protocol << "] " << "Retrieving emails IDs" << std::endl;

	std::string gmail_smtp_host(gmail_imap.begin(), gmail_imap.end());

	ids = libcurl::get_emails_ids(gmail_username, gmail_password, gmail_smtp_host, "UID SEARCH (SUBJECT '" + PoC_KEYWORD + "')", uagent, false);

	std::wcout << "[DEXTER][" << protocol << "] " << "Retrieving emails" << std::endl;

	for (i = 0; i < ids.size(); i++) {
		if (libcurl::receive_email(&m, ids[i], gmail_imap_inbox_obj, gmail_username, gmail_password, uagent, false)) {

			std::string value(m->body);
			std::string tosearch = "protocol=GMAIL&data=";
			std::string replace = "";
			size_t pos = value.find(tosearch);
			while (pos != std::string::npos)
			{
				value.replace(pos, tosearch.size(), replace);
				pos = value.find(tosearch, pos + tosearch.size());
			}

			handle_data(value, aespassword, protocol);
		}
	}

	libcurl::finalize();
}

void libreporter::test_ftp_protocol(std::wstring host, WORD port, std::wstring username, std::wstring password, std::set<std::wstring> uagents, std::string aespassword, std::wstring directory,
	std::string PoC_KEYWORD) {

	HINTERNET internet = NULL, connection = NULL;
	std::wstring protocol = L"FTP";

	if (!check_tcp_server_connectivity(protocol, host, port)) {
		return;
	}

	std::wstring useragent = pick_random_useragent(uagents, protocol);
	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Connecting to " << protocol << L" server" << std::endl;

	bool result = false;

	internet = libftp::open(useragent);

	if (internet != NULL) {
		connection = libftp::connect(internet, host, port, username, password);
	}

	std::wcout << "[DEXTER][" << protocol << "][WARNING] " << "Transmitting unencrypted data over " << protocol << std::endl;

	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Setting working directory" << std::endl;

	if (connection != NULL) {
		result = libftp::set_current_dir(connection, directory.c_str());
	}

	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Reading file" << std::endl;

	std::string data = "";

	if (result) {
		std::wstring filename(PoC_KEYWORD.begin(), PoC_KEYWORD.end());
		data = libftp::read_file(connection, filename + L".txt");

		std::string proto(protocol.begin(), protocol.end());

		std::string value(data);
		std::string tosearch = "protocol=" + proto + "&data=";
		std::string replace = "";
		size_t pos = value.find(tosearch);
		while (pos != std::string::npos)
		{
			value.replace(pos, tosearch.size(), replace);
			pos = value.find(tosearch, pos + tosearch.size());
		}

		handle_data(value, aespassword, protocol);
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

void libreporter::test_ftps_protocol(std::wstring host, WORD port, std::string username, std::string password, std::set<std::wstring> uagents, std::string aespassword,
	std::string directory, std::string PoC_KEYWORD, bool ignore_unknown_ca) {

	bool result = false;

	std::wstring protocol = L"FTPS";

	if (!check_tcp_server_connectivity(protocol, host, port)) {
		return;
	}

	libcurl::init();

	std::wstring useragent = pick_random_useragent(uagents, protocol);
	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Connecting to " << protocol << L" server" << std::endl;

	std::string uagent(useragent.begin(), useragent.end());

	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Reading file" << std::endl;

	std::string ftps_host(host.begin(), host.end());

	std::string data = libcurl::ftps_download(directory, PoC_KEYWORD + ".txt", username, password, ftps_host, port, uagent, ignore_unknown_ca);

	std::string proto(protocol.begin(), protocol.end());

	std::string value(data);
	std::string tosearch = "protocol=" + proto + "&data=";
	std::string replace = "";
	size_t pos = value.find(tosearch);
	while (pos != std::string::npos)
	{
		value.replace(pos, tosearch.size(), replace);
		pos = value.find(tosearch, pos + tosearch.size());
	}

	handle_data(value, aespassword, protocol);

	libcurl::finalize();
}

void libreporter::test_smtp_protocol(std::wstring host, WORD port, std::wstring imap_host, std::string imap_inbox_obj, std::string username, std::string password, std::string name,
	std::set<std::wstring> uagents, std::string aespassword, std::string PoC_KEYWORD, bool OverTls, bool ignore_unknown_ca) {

	int total = 0;
	int i = 0;
	MimeMessage *m = 0;
	std::vector<int> ids;

	std::wstring protocol = (OverTls ? L"SMTPS" : L"SMTP");

	if (!check_tcp_server_connectivity(protocol, host, port)) {
		return;
	}

	libcurl::init();

	std::wstring useragent = pick_random_useragent(uagents, protocol);

	std::wcout << "[DEXTER][" << protocol << "] " << "Connecting to " << protocol << " server" << std::endl;

	std::wcout << "[DEXTER][" << protocol << "] " << "Sending data with " << protocol << " packet" << std::endl;

	std::string uagent(useragent.begin(), useragent.end());

	std::wcout << "[DEXTER][" << protocol << "] " << "Retrieving emails IDs" << std::endl;

	std::string my_imap_host(imap_host.begin(), imap_host.end());

	ids = libcurl::get_emails_ids(username, password, my_imap_host, "UID SEARCH SUBJECT \"" + PoC_KEYWORD + "\"", uagent, ignore_unknown_ca);

	std::wcout << "[DEXTER][" << protocol << "] " << "Retrieving emails" << std::endl;

	bool found = false;
	for (i = 0; i < ids.size(); i++) {
		if (libcurl::receive_email(&m, ids[i], imap_inbox_obj, username, password, uagent, ignore_unknown_ca)) {

			std::string value(m->body);
			std::string proto(protocol.begin(), protocol.end());
			std::string tosearch = "protocol=" + proto + "&data=";
			std::string replace = "";
			size_t pos = value.find(tosearch);
			while (pos != std::string::npos)
			{
				found = true;
				value.replace(pos, tosearch.size(), replace);
				pos = value.find(tosearch, pos + tosearch.size());
			}

			if (found) {
				handle_data(value, aespassword, protocol);
				found = false;
			}
		}
	}

	libcurl::finalize();
}

void libreporter::test_git_over_ssh_protocol(std::wstring host, WORD port, std::wstring url, std::string username, std::string password,
	std::string email, std::string folder, std::string aespassword, std::string PoC_KEYWORD) {

	std::wstring protocol = L"GIT";

	if (!check_tcp_server_connectivity(protocol, host, port)) {
		return;
	}

	libgit::init();

	std::vector<std::string> messages;
	bool found = false;

	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Connecting to " << protocol << L" server" << std::endl;
	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Sending data with " << protocol << L" packet" << std::endl;
	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Reading commits" << std::endl;
	std::wcout << L"[DEXTER][" << protocol << L"] " << L"Retrieving commits messages" << std::endl;

	std::string git_url(url.begin(), url.end());

	messages = libgit::commit_messages(username, password, git_url, folder);

	for (int i = 0; i < messages.size(); i++) {

		std::string value(messages[i]);
		std::string proto(protocol.begin(), protocol.end());
		std::string tosearch = "protocol=" + proto + "&data=";
		std::string replace = "";
		size_t pos = value.find(tosearch);
		while (pos != std::string::npos)
		{
			found = true;
			value.replace(pos, tosearch.size(), replace);
			pos = value.find(tosearch, pos + tosearch.size());
		}

		if (found) {
			handle_data(value, aespassword, protocol);
			found = false;
		}
	}

	libgit::finalize();
}

void libreporter::test_tcp_protocol(std::wstring host, int port, std::string aespassword, std::string PoC_KEYWORD) {

}
