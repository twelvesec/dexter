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

#include <iostream>
#include <windows.h>
#include <fstream>

#include "libagent.h"
#include "rapidjson/document.h"
#include "common/helper.h"

#define VERSION "1.0"

std::wstring CONFIG_FILE;
std::wstring USER_AGENTS;

void Usage(char *appname);
int PargeArgs(int argc, char *argv[]);

int main(int argc, char *argv[])
{
	std::cout << std::endl;
	std::cout << "---------------------------------------------------------------" << std::endl;
	std::cout << "  Dexter agent v." << VERSION << " - Data EXfiltration TestER" << std::endl;
	std::cout << "---------------------------------------------------------------" << std::endl << std::endl;

	PargeArgs(argc, argv);

	rapidjson::Document d;
	std::string config_file_content = helper::load_json_file(CONFIG_FILE);
	d.Parse(config_file_content.c_str());

	std::string AES_KEY = helper::read_string_value_ascii(&d, "AES_KEY");
	bool IGNORE_CERT_UNKNOWN_CA = helper::read_bool_value(&d, "IGNORE_CERT_UNKNOWN_CA");
	bool IGNORE_CERT_DATE_INVALID = helper::read_bool_value(&d, "IGNORE_CERT_DATE_INVALID");

	std::wstring HTTP_host = helper::read_object_string_value(&d, "HTTP", "host");
	WORD HTTP_port = helper::read_object_word_value(&d, "HTTP", "port");

	WORD HTTP_clientid = helper::read_object_word_value(&d, "HTTP", "clientid");
	std::string HTTP_secret = helper::read_object_string_value_ascii(&d, "HTTP", "secret");
	std::string HTTP_username = helper::read_object_string_value_ascii(&d, "HTTP", "username");
	std::string HTTP_password = helper::read_object_string_value_ascii(&d, "HTTP", "password");
	std::wstring HTTP_method = helper::read_object_string_value(&d, "HTTP", "method");
	std::wstring HTTP_token_uri = helper::read_object_string_value(&d, "HTTP", "token_uri");
	std::wstring HTTP_logclient_uri = helper::read_object_string_value(&d, "HTTP", "logclient_uri");

	std::wstring HTTPs_host = helper::read_object_string_value(&d, "HTTPS", "host");
	WORD HTTPs_port = helper::read_object_word_value(&d, "HTTPS", "port");

	WORD HTTPs_clientid = helper::read_object_word_value(&d, "HTTPS", "clientid");
	std::string HTTPs_secret = helper::read_object_string_value_ascii(&d, "HTTPS", "secret");
	std::string HTTPs_username = helper::read_object_string_value_ascii(&d, "HTTPS", "username");
	std::string HTTPs_password = helper::read_object_string_value_ascii(&d, "HTTPS", "password");
	std::wstring HTTPs_method = helper::read_object_string_value(&d, "HTTPS", "method");
	std::wstring HTTPs_token_uri = helper::read_object_string_value(&d, "HTTPS", "token_uri");
	std::wstring HTTPs_logclient_uri = helper::read_object_string_value(&d, "HTTPS", "logclient_uri");

	std::set<std::wstring> useragents = helper::load_useragent_strings(USER_AGENTS);

	// HTTP

	std::cout << "----------------------------------" << std::endl;
	std::cout << "  Using HTTP as transport method" << std::endl;
	std::cout << "----------------------------------" << std::endl << std::endl;
	libagent::test_http_protocol(HTTP_host, HTTP_port, HTTP_method, HTTP_token_uri, HTTP_logclient_uri, useragents, HTTP_clientid,
		HTTP_secret, HTTP_username, HTTP_password, IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, false);
	std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;


	Sleep(1000);


	// HTTPS

	std::cout << "----------------------------------" << std::endl;
	std::cout << "  Using HTTPs as transport method" << std::endl;
	std::cout << "----------------------------------" << std::endl << std::endl;
	libagent::test_http_protocol(HTTPs_host, HTTPs_port, HTTPs_method, HTTPs_token_uri, HTTPs_logclient_uri, useragents, HTTPs_clientid,
		HTTPs_secret, HTTPs_username, HTTPs_password, IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, false);
	std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;

	return 0;
}

void Usage(char *appname) {
	std::cout << " Usage: " << appname << " [options] ..." << std::endl << std::endl;
	std::cout << " -c <configuration file>         " << "A JSON formatted configuration file." << std::endl;
	std::cout << " -u <User-Agent strings file>    " << "A text file containing user-agent strings." << std::endl;
	std::cout << std::endl;
}

int PargeArgs(int argc, char *argv[]) {
	int argsCount;
	LPWSTR *args = CommandLineToArgvW(GetCommandLineW(), &argsCount);

	if (args == NULL || argc < 5) {
		Usage(argv[0]);
		return -1;
	}

	for (int i = 0; i < argsCount; i++) {
		if (args[i] != NULL && args[i][0] == '-') {
			switch (args[i][1]) {
			case 'c':
				i++;
				if (i < argc && args[i] != NULL && args[i][0] != '-') {
					CONFIG_FILE = std::wstring(args[i]);
				}
				break;
			case 'u':
				i++;
				if (i < argc && args[i] != NULL && args[i][0] != '-') {
					USER_AGENTS = std::wstring(args[i]);
				}
				break;
			default:
				Usage(argv[0]);
				return -1;

			}
		}
	}
	LocalFree(args);

	return 0;
}
