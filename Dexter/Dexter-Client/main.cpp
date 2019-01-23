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

#include "rapidjson/document.h"
#include "helper.h"
#include "libagent.h"

#define VERSION "1.0"

std::wstring CONFIG_FILE;
std::wstring USER_AGENTS;
std::wstring PROTOCOL;

void Usage(char *appname);
int PargeArgs(int argc, char *argv[]);

int main(int argc, char *argv[]) {

	std::cout << std::endl << std::endl <<
		R"(___________              .__                _________              )" << std::endl <<
		R"(\__    ___/_  _  __ ____ |  |___  __ ____  /   _____/ ____   ____  )" << std::endl <<
		R"(  |    |  \ \/ \/ // __ \|  |\  \/ // __ \ \_____  \_/ __ \_/ ___\ )" << std::endl <<
		R"(  |    |   \     /\  ___/|  |_\   /\  ___/ /        \  ___/\  \___ )" << std::endl <<
		R"(  |____|    \/\_/  \___  >____/\_/  \___  >_______  /\___  >\___  >)" << std::endl <<
		R"(                       \/               \/        \/     \/     \/ )" << std::endl << std::endl;
	std::cout << "----------------------------------------------------------------" << std::endl;
	std::cout << "  Dexter agent v." << VERSION << " - Data EXfiltration TestER" << std::endl;
	std::cout << "  Dexter is an open source tool licensed under GPLv3." << std::endl;
	std::cout << "  Written by : @maldevel" << std::endl;
	std::cout << "  https ://www.twelvesec.com/" << std::endl;
	std::cout << "  Please visit https://github.com/twelvesec/dexter for more.." << std::endl;
	std::cout << "----------------------------------------------------------------" << std::endl << std::endl;

	if (PargeArgs(argc, argv) == -1) {
		return -1;
	}

	rapidjson::Document d;
	std::string config_file_content = helper::load_json_file(CONFIG_FILE);
	d.Parse(config_file_content.c_str());

	std::string AES_PASSWORD = helper::read_string_value_ascii(&d, "AES_PASSWORD");
	std::string PoC_KEYWORD = helper::read_string_value_ascii(&d, "PoC_KEYWORD");
	bool IGNORE_CERT_UNKNOWN_CA = helper::read_bool_value(&d, "IGNORE_CERT_UNKNOWN_CA");
	bool IGNORE_CERT_DATE_INVALID = helper::read_bool_value(&d, "IGNORE_CERT_DATE_INVALID");

	//http
	std::wstring HTTP_host = helper::read_object_string_value(&d, "HTTP", "host");
	WORD HTTP_port = helper::read_object_word_value(&d, "HTTP", "port");

	WORD HTTP_clientid = helper::read_object_word_value(&d, "HTTP", "clientid");
	std::string HTTP_secret = helper::read_object_string_value_ascii(&d, "HTTP", "secret");
	std::string HTTP_username = helper::read_object_string_value_ascii(&d, "HTTP", "username");
	std::string HTTP_password = helper::read_object_string_value_ascii(&d, "HTTP", "password");

	std::wstring HTTP_token_uri_method = helper::read_object_string_value(&d, "HTTP", "token_uri_method");
	std::wstring HTTP_logclient_uri_method = helper::read_object_string_value(&d, "HTTP", "logclient_uri_method");

	std::wstring HTTP_token_uri = helper::read_object_string_value(&d, "HTTP", "token_uri");
	std::wstring HTTP_logclient_uri = helper::read_object_string_value(&d, "HTTP", "logclient_uri");

	//https
	std::wstring HTTPs_host = helper::read_object_string_value(&d, "HTTPS", "host");
	WORD HTTPs_port = helper::read_object_word_value(&d, "HTTPS", "port");

	WORD HTTPs_clientid = helper::read_object_word_value(&d, "HTTPS", "clientid");
	std::string HTTPs_secret = helper::read_object_string_value_ascii(&d, "HTTPS", "secret");
	std::string HTTPs_username = helper::read_object_string_value_ascii(&d, "HTTPS", "username");
	std::string HTTPs_password = helper::read_object_string_value_ascii(&d, "HTTPS", "password");

	std::wstring HTTPs_token_uri_method = helper::read_object_string_value(&d, "HTTPS", "token_uri_method");
	std::wstring HTTPs_logclient_uri_method = helper::read_object_string_value(&d, "HTTPS", "logclient_uri_method");

	std::wstring HTTPs_token_uri = helper::read_object_string_value(&d, "HTTPS", "token_uri");
	std::wstring HTTPs_logclient_uri = helper::read_object_string_value(&d, "HTTPS", "logclient_uri");

	//gmail
	std::string Gmail_smtp = helper::read_object_string_value_ascii(&d, "GMAIL", "smtp");
	std::string Gmail_username = helper::read_object_string_value_ascii(&d, "GMAIL", "username");
	std::string Gmail_password = helper::read_object_string_value_ascii(&d, "GMAIL", "password");
	std::string Gmail_name = helper::read_object_string_value_ascii(&d, "GMAIL", "name");

	//ftp
	std::wstring FTP_host = helper::read_object_string_value(&d, "FTP", "host");
	WORD FTP_port = helper::read_object_word_value(&d, "FTP", "port");
	std::wstring FTP_username = helper::read_object_string_value(&d, "FTP", "username");
	std::wstring FTP_password = helper::read_object_string_value(&d, "FTP", "password");
	std::wstring FTP_workingdir = helper::read_object_string_value(&d, "FTP", "working_dir");

	//ftps
	std::string FTPs_host = helper::read_object_string_value_ascii(&d, "FTPS", "host");
	WORD FTPs_port = helper::read_object_word_value(&d, "FTPS", "port");
	std::string FTPs_username = helper::read_object_string_value_ascii(&d, "FTPS", "username");
	std::string FTPs_password = helper::read_object_string_value_ascii(&d, "FTPS", "password");
	std::string FTPs_workingdir = helper::read_object_string_value_ascii(&d, "FTPS", "working_dir");

	//smtp
	std::string SMTP_host = helper::read_object_string_value_ascii(&d, "SMTP", "smtp");
	std::string SMTP_username = helper::read_object_string_value_ascii(&d, "SMTP", "username");
	std::string SMTP_password = helper::read_object_string_value_ascii(&d, "SMTP", "password");
	std::string SMTP_name = helper::read_object_string_value_ascii(&d, "SMTP", "name");

	//smtps
	std::string SMTPs_host = helper::read_object_string_value_ascii(&d, "SMTPS", "smtp");
	std::string SMTPs_username = helper::read_object_string_value_ascii(&d, "SMTPS", "username");
	std::string SMTPs_password = helper::read_object_string_value_ascii(&d, "SMTPS", "password");
	std::string SMTPs_name = helper::read_object_string_value_ascii(&d, "SMTPS", "name");


	//git
	std::string GIT_url = helper::read_object_string_value_ascii(&d, "GIT", "url");
	std::string GIT_username = helper::read_object_string_value_ascii(&d, "GIT", "username");
	std::string GIT_password = helper::read_object_string_value_ascii(&d, "GIT", "password");
	std::string GIT_email = helper::read_object_string_value_ascii(&d, "GIT", "email");
	std::string GIT_workingdir = helper::read_object_string_value_ascii(&d, "GIT", "workingdir");

	std::set<std::wstring> useragents = helper::load_useragent_strings(USER_AGENTS);

	// HTTP
	if (PROTOCOL == L"HTTP" || PROTOCOL == L"ALL") {
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "  Using HTTP as transport method" << std::endl;
		std::cout << "-----------------------------------" << std::endl << std::endl;

		libagent::test_http_protocol(HTTP_host, HTTP_port, HTTP_token_uri_method, HTTP_logclient_uri_method,
			HTTP_token_uri, HTTP_logclient_uri, useragents, HTTP_clientid, HTTP_secret, HTTP_username, HTTP_password, AES_PASSWORD,
			PoC_KEYWORD, IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, false);

		std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;

		Sleep(1000);
	}

	// HTTPS
	if (PROTOCOL == L"HTTPS" || PROTOCOL == L"ALL") {
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "  Using HTTPs as transport method" << std::endl;
		std::cout << "-----------------------------------" << std::endl << std::endl;

		libagent::test_http_protocol(HTTPs_host, HTTPs_port, HTTPs_token_uri_method, HTTPs_logclient_uri_method, HTTPs_token_uri,
			HTTPs_logclient_uri, useragents, HTTPs_clientid, HTTPs_secret, HTTPs_username, HTTPs_password, AES_PASSWORD, PoC_KEYWORD,
			IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, true);

		std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;

		Sleep(1000);
	}

	// SMTPS - GMAIL
	if (PROTOCOL == L"GMAIL" || PROTOCOL == L"ALL") {
		std::cout << "-------------------------------------------" << std::endl;
		std::cout << "  Using SMTPS (GMAIL) as transport method" << std::endl;
		std::cout << "-------------------------------------------" << std::endl << std::endl;

		libagent::test_gmail_protocol(Gmail_smtp, Gmail_username, Gmail_password, Gmail_name, useragents, AES_PASSWORD, PoC_KEYWORD);

		std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;

		Sleep(1000);
	}

	// FTP
	if (PROTOCOL == L"FTP" || PROTOCOL == L"ALL") {
		std::cout << "-------------------------------------------" << std::endl;
		std::cout << "  Using FTP as transport method" << std::endl;
		std::cout << "-------------------------------------------" << std::endl << std::endl;

		libagent::test_ftp_protocol(FTP_host, FTP_port, FTP_username, FTP_password, useragents, AES_PASSWORD, FTP_workingdir, PoC_KEYWORD);

		std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;

		Sleep(1000);
	}

	// FTPS
	if (PROTOCOL == L"FTPS" || PROTOCOL == L"ALL") {
		std::cout << "-------------------------------------------" << std::endl;
		std::cout << "  Using FTPs as transport method" << std::endl;
		std::cout << "-------------------------------------------" << std::endl << std::endl;

		libagent::test_ftps_protocol(FTPs_host, FTPs_port, FTPs_username, FTPs_password, useragents, AES_PASSWORD, FTPs_workingdir, PoC_KEYWORD, IGNORE_CERT_UNKNOWN_CA);

		std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;

		Sleep(1000);
	}

	// SMTP
	if (PROTOCOL == L"SMTP" || PROTOCOL == L"ALL") {
		std::cout << "-------------------------------------------" << std::endl;
		std::cout << "  Using SMTP as transport method" << std::endl;
		std::cout << "-------------------------------------------" << std::endl << std::endl;

		libagent::test_smtp_protocol(SMTP_host, SMTP_username, SMTP_password, SMTP_name, useragents, AES_PASSWORD, PoC_KEYWORD, false, IGNORE_CERT_UNKNOWN_CA);

		std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;

		Sleep(1000);
	}

	// SMTPS
	if (PROTOCOL == L"SMTPS" || PROTOCOL == L"ALL") {
		std::cout << "-------------------------------------------" << std::endl;
		std::cout << "  Using SMTPs as transport method" << std::endl;
		std::cout << "-------------------------------------------" << std::endl << std::endl;

		libagent::test_smtp_protocol(SMTPs_host, SMTPs_username, SMTPs_password, SMTPs_name, useragents, AES_PASSWORD, PoC_KEYWORD, true, IGNORE_CERT_UNKNOWN_CA);

		std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;

		Sleep(1000);
	}

	// git
	if (PROTOCOL == L"GIT" || PROTOCOL == L"ALL") {
		std::cout << "-------------------------------------------" << std::endl;
		std::cout << "  Using Git as transport method" << std::endl;
		std::cout << "-------------------------------------------" << std::endl << std::endl;

		libagent::test_git_over_ssh_protocol(GIT_url, GIT_username, GIT_password, GIT_email, GIT_workingdir, AES_PASSWORD, PoC_KEYWORD);

		std::cout << std::endl << "-------------------------------------------" << std::endl << std::endl;
	}

	return 0;
}

void Usage(char *appname) {
	std::cout << " Usage: " << appname << " [options] ..." << std::endl << std::endl;
	std::cout << " -c <configuration file>         " << "A JSON formatted configuration file." << std::endl;
	std::cout << " -u <User-Agent strings file>    " << "A text file containing user-agent strings." << std::endl;
	std::cout << " -p <Protocol>                   " << "Choose a specific protocol e.g. HTTP to test or ALL to test all protocols." << std::endl;
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
			case 'p':
				i++;
				if (i < argc && args[i] != NULL && args[i][0] != '-') {
					PROTOCOL = std::wstring(args[i]);
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
