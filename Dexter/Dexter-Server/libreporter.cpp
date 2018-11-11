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

#include "libreporter.h"
#include "libhttp.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "helper.h"
#include "libcrypt.h"

#include <iostream>

static void handle_data(std::string data, std::string password, bool HTTPS_CONNECTION) {
	char **details = { 0 };
	int splitted = 0;
	std::string decrypted_data = libcrypt::decrypt(password, data);

	if (!HTTPS_CONNECTION) {
		std::cout << "[HTTP] " << "Received HTTP packet. Details: ";
	}
	else {
		std::cout << "[HTTPS] " << "Received HTTPS packet. Details: ";
	}

	if ((splitted = helper::SplitString(decrypted_data.c_str(), (DWORD)decrypted_data.length(), "&", &details)) != -1) {
		for (int i = 0; i < splitted; i++) {
			if (i == splitted - 1) {
				std::cout << details[i];
			}
			else {
				std::cout << details[i] << ", ";
			}
		}
	}

	if (details) {
		for (int i = 0; i < splitted; i++) {
			HeapFree(GetProcessHeap(), 0, details[i]);
			details[i] = NULL;
		}

		HeapFree(GetProcessHeap(), 0, details);
		details = NULL;
	}

	std::cout << std::endl;
}

void libreporter::test_http_protocol(std::wstring host, WORD port, std::wstring token_uri_method, std::wstring clients_uri_method, std::wstring tokenuri,
	std::wstring clients_uri, std::set<std::wstring> uagents, WORD clientid, std::string secret, std::string username,
	std::string password, std::string aespassword, std::string PoC_KEYWORD, bool IGNORE_CERT_UNKNOWN_CA, bool IGNORE_CERT_DATE_INVALID,
	bool HTTPS_CONNECTION) {

	char *downloaded = 0;
	HINTERNET internet = NULL, connection = NULL, request = NULL;
	const WCHAR *token_headers = L"Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n";
	bool result = false;

	std::wstring useragent = helper::pick_random_useragent_fromfile(uagents);
	std::wcout << "[HTTP] " << "User-Agent: " << useragent << std::endl;

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
		std::wstring clients_headers = L"Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nAuthorization: Bearer " +
			access_token + L"\r\nConnection: close\r\n";

		if (!HTTPS_CONNECTION) {
			std::wcout << "[HTTP] " << "Sending data with HTTP packet" << std::endl;
		}
		else {
			std::wcout << "[HTTPS] " << "Sending data with HTTPS packet" << std::endl;
		}

		if (connection != NULL) {
			request = libhttp::json_request(connection, clients_uri_method, clients_uri, NULL,
				clients_headers.c_str(), IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, HTTPS_CONNECTION);
		}

		if (request != NULL) {
			result = libhttp::retrieve_data(request, &downloaded);
		}

		if (result && downloaded != NULL) {
			rapidjson::Document clients_response;
			clients_response.Parse(downloaded);

			if (helper::read_bool_value(&clients_response, "success") == true) {

				if (!HTTPS_CONNECTION) {
					std::wcout << "[HTTP] " << "Transmission succeeded" << std::endl;
				}
				else {
					std::wcout << "[HTTPS] " << "Transmission succeeded" << std::endl;
				}

				if (clients_response.HasMember("data") && clients_response["data"].IsArray()) {
					const rapidjson::Value& a = clients_response["data"].GetArray();
					for (rapidjson::SizeType i = 0; i < a.Size(); i++) {
						if (a[i].IsObject()) {
							for (rapidjson::Value::ConstMemberIterator itr = a[i].MemberBegin(); itr != a[i].MemberEnd(); ++itr) {
								if (itr->name != NULL) {
									std::string val(itr->name.GetString());
									if (val == "data" && itr->value != NULL) {
										handle_data(itr->value.GetString(), aespassword, HTTPS_CONNECTION);
									}
								}
							}
						}
					}
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

