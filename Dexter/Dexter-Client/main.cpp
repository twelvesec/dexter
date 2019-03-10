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
#include "libnet.h"

#define VERSION "1.0"

std::wstring CONFIG_FILE;
std::wstring USER_AGENTS;
std::wstring PROTOCOL;
std::string config_file_content;

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

	if ((config_file_content = helper::load_json_file(CONFIG_FILE)) == "") {
		std::wcout << "[DEXTER]" << " Please provide a valid configuration file (" << CONFIG_FILE << ")" << std::endl;
		return -1;
	}

	d.Parse(config_file_content.c_str());

	std::string AES_PASSWORD = helper::read_string_value_ascii(&d, "AES_PASSWORD");
	std::string PoC_KEYWORD = helper::read_string_value_ascii(&d, "PoC_KEYWORD");
	bool IGNORE_CERT_UNKNOWN_CA = helper::read_bool_value(&d, "IGNORE_CERT_UNKNOWN_CA");
	bool IGNORE_CERT_DATE_INVALID = helper::read_bool_value(&d, "IGNORE_CERT_DATE_INVALID");

	std::set<std::wstring> useragents = helper::load_useragent_strings(USER_AGENTS);

	if (useragents.size() == 0) {
		std::wcout << "[DEXTER]" << " Please provide a valid User-Agent Strings file (" << USER_AGENTS << ")" << std::endl;
		return -1;
	}

	if (!libnet::init()) {
		std::wcout << "[DEXTER]" << " Failed to initialize network library" << std::endl;
		return -1;
	}

	// HTTP
	if (PROTOCOL == L"HTTP" || PROTOCOL == L"ALL") {

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

		if (HTTP_host == L"" || HTTP_port == -1 || HTTP_clientid == -1 || HTTP_secret == "" || HTTP_username == "" || HTTP_password == "" || HTTP_token_uri_method == L"" ||
			HTTP_logclient_uri_method == L"" || HTTP_token_uri == L"" || HTTP_logclient_uri == L"") {

			std::wcout << "[DEXTER][" << PROTOCOL << "]" << " It appears something is wrong with the configuration file" << std::endl;
			libnet::finalize();
			return -1;
		}

		std::wcout << "[DEXTER]" << " Using " << PROTOCOL << " as transport method" << std::endl;

		libagent::test_http_protocol(HTTP_host, HTTP_port, HTTP_token_uri_method, HTTP_logclient_uri_method,
			HTTP_token_uri, HTTP_logclient_uri, useragents, HTTP_clientid, HTTP_secret, HTTP_username, HTTP_password, AES_PASSWORD,
			PoC_KEYWORD, IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, false);

		Sleep(1000);
	}

	// HTTPS
	if (PROTOCOL == L"HTTPS" || PROTOCOL == L"ALL") {

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

		if (HTTPs_host == L"" || HTTPs_port == -1 || HTTPs_clientid == -1 || HTTPs_secret == "" || HTTPs_username == "" || HTTPs_password == "" || HTTPs_token_uri_method == L"" ||
			HTTPs_logclient_uri_method == L"" || HTTPs_token_uri == L"" || HTTPs_logclient_uri == L"") {

			std::wcout << "[DEXTER][" << PROTOCOL << "]" << " It appears something is wrong with the configuration file" << std::endl;
			libnet::finalize();
			return -1;
		}

		std::wcout << "[DEXTER]" << " Using " << PROTOCOL << " as transport method" << std::endl;

		libagent::test_http_protocol(HTTPs_host, HTTPs_port, HTTPs_token_uri_method, HTTPs_logclient_uri_method, HTTPs_token_uri,
			HTTPs_logclient_uri, useragents, HTTPs_clientid, HTTPs_secret, HTTPs_username, HTTPs_password, AES_PASSWORD, PoC_KEYWORD,
			IGNORE_CERT_UNKNOWN_CA, IGNORE_CERT_DATE_INVALID, true);

		Sleep(1000);
	}

	// SMTPS - GMAIL
	if (PROTOCOL == L"GMAIL" || PROTOCOL == L"ALL") {

		std::wstring Gmail_host = helper::read_object_string_value(&d, "GMAILSMTP", "host");
		WORD Gmail_port = helper::read_object_word_value(&d, "GMAILSMTP", "port");
		std::wstring Gmail_smtp = helper::read_object_string_value(&d, "GMAILSMTP", "smtp");
		std::string Gmail_username = helper::read_object_string_value_ascii(&d, "GMAILSMTP", "username");
		std::string Gmail_password = helper::read_object_string_value_ascii(&d, "GMAILSMTP", "password");
		std::string Gmail_name = helper::read_object_string_value_ascii(&d, "GMAILSMTP", "name");

		if (Gmail_host == L"" || Gmail_port == -1 || Gmail_smtp == L"" || Gmail_username == "" || Gmail_password == "" || Gmail_name == "") {

			std::wcout << "[DEXTER][" << PROTOCOL << "]" << " It appears something is wrong with the configuration file" << std::endl;
			libnet::finalize();
			return -1;
		}

		std::wcout << "[DEXTER]" << " Using " << PROTOCOL << " as transport method" << std::endl;

		libagent::test_gmail_protocol(Gmail_host, Gmail_port, Gmail_smtp, Gmail_username, Gmail_password, Gmail_name, useragents, AES_PASSWORD, PoC_KEYWORD);

		Sleep(1000);
	}

	// FTP
	if (PROTOCOL == L"FTP" || PROTOCOL == L"ALL") {

		std::wstring FTP_host = helper::read_object_string_value(&d, "FTP", "host");
		WORD FTP_port = helper::read_object_word_value(&d, "FTP", "port");
		std::wstring FTP_username = helper::read_object_string_value(&d, "FTP", "username");
		std::wstring FTP_password = helper::read_object_string_value(&d, "FTP", "password");
		std::wstring FTP_workingdir = helper::read_object_string_value(&d, "FTP", "working_dir");

		if (FTP_host == L"" || FTP_port == -1 || FTP_username == L"" || FTP_password == L"" || FTP_workingdir == L"") {

			std::wcout << "[DEXTER][" << PROTOCOL << "]" << " It appears something is wrong with the configuration file" << std::endl;
			libnet::finalize();
			return -1;
		}

		std::wcout << "[DEXTER]" << " Using " << PROTOCOL << " as transport method" << std::endl;

		libagent::test_ftp_protocol(FTP_host, FTP_port, FTP_username, FTP_password, useragents, AES_PASSWORD, FTP_workingdir, PoC_KEYWORD);

		Sleep(1000);
	}

	// FTPS
	if (PROTOCOL == L"FTPS" || PROTOCOL == L"ALL") {

		std::wstring FTPs_host = helper::read_object_string_value(&d, "FTPS", "host");
		WORD FTPs_port = helper::read_object_word_value(&d, "FTPS", "port");
		std::string FTPs_username = helper::read_object_string_value_ascii(&d, "FTPS", "username");
		std::string FTPs_password = helper::read_object_string_value_ascii(&d, "FTPS", "password");
		std::string FTPs_workingdir = helper::read_object_string_value_ascii(&d, "FTPS", "working_dir");

		if (FTPs_host == L"" || FTPs_port == -1 || FTPs_username == "" || FTPs_password == "" || FTPs_workingdir == "") {

			std::wcout << "[DEXTER][" << PROTOCOL << "]" << " It appears something is wrong with the configuration file" << std::endl;
			libnet::finalize();
			return -1;
		}

		std::wcout << "[DEXTER]" << " Using " << PROTOCOL << " as transport method" << std::endl;

		libagent::test_ftps_protocol(FTPs_host, FTPs_port, FTPs_username, FTPs_password, useragents, AES_PASSWORD, FTPs_workingdir, PoC_KEYWORD, IGNORE_CERT_UNKNOWN_CA);

		Sleep(1000);
	}

	// SMTP
	if (PROTOCOL == L"SMTP" || PROTOCOL == L"ALL") {

		std::wstring SMTP_host = helper::read_object_string_value(&d, "SMTP", "host");
		WORD SMTP_port = helper::read_object_word_value(&d, "SMTP", "port");
		std::wstring SMTP_addr = helper::read_object_string_value(&d, "SMTP", "smtp");
		std::string SMTP_username = helper::read_object_string_value_ascii(&d, "SMTP", "username");
		std::string SMTP_password = helper::read_object_string_value_ascii(&d, "SMTP", "password");
		std::string SMTP_name = helper::read_object_string_value_ascii(&d, "SMTP", "name");

		if (SMTP_host == L"" || SMTP_port == -1 || SMTP_addr == L"" || SMTP_username == "" || SMTP_password == "" || SMTP_name == "") {

			std::wcout << "[DEXTER][" << PROTOCOL << "]" << " It appears something is wrong with the configuration file" << std::endl;
			libnet::finalize();
			return -1;
		}

		std::wcout << "[DEXTER]" << " Using " << PROTOCOL << " as transport method" << std::endl;

		libagent::test_smtp_protocol(SMTP_host, SMTP_port, SMTP_addr, SMTP_username, SMTP_password, SMTP_name, useragents, AES_PASSWORD, PoC_KEYWORD, false, IGNORE_CERT_UNKNOWN_CA);

		Sleep(1000);
	}

	// SMTPS
	if (PROTOCOL == L"SMTPS" || PROTOCOL == L"ALL") {

		std::wstring SMTPs_host = helper::read_object_string_value(&d, "SMTPS", "host");
		WORD SMTPs_port = helper::read_object_word_value(&d, "SMTPS", "port");
		std::wstring SMTPs_addr = helper::read_object_string_value(&d, "SMTPS", "smtp");
		std::string SMTPs_username = helper::read_object_string_value_ascii(&d, "SMTPS", "username");
		std::string SMTPs_password = helper::read_object_string_value_ascii(&d, "SMTPS", "password");
		std::string SMTPs_name = helper::read_object_string_value_ascii(&d, "SMTPS", "name");

		if (SMTPs_host == L"" || SMTPs_port == -1 || SMTPs_addr == L"" || SMTPs_username == "" || SMTPs_password == "" || SMTPs_name == "") {

			std::wcout << "[DEXTER][" << PROTOCOL << "]" << " It appears something is wrong with the configuration file" << std::endl;
			libnet::finalize();
			return -1;
		}

		std::wcout << "[DEXTER]" << " Using " << PROTOCOL << " as transport method" << std::endl;

		libagent::test_smtp_protocol(SMTPs_host, SMTPs_port, SMTPs_addr, SMTPs_username, SMTPs_password, SMTPs_name, useragents, AES_PASSWORD, PoC_KEYWORD, true, IGNORE_CERT_UNKNOWN_CA);

		Sleep(1000);
	}

	// git
	if (PROTOCOL == L"GIT" || PROTOCOL == L"ALL") {

		std::wstring GIT_host = helper::read_object_string_value(&d, "GIT", "host");
		WORD GIT_port = helper::read_object_word_value(&d, "GIT", "port");
		std::wstring GIT_url = helper::read_object_string_value(&d, "GIT", "url");
		std::string GIT_username = helper::read_object_string_value_ascii(&d, "GIT", "username");
		std::string GIT_password = helper::read_object_string_value_ascii(&d, "GIT", "password");
		std::string GIT_email = helper::read_object_string_value_ascii(&d, "GIT", "email");
		std::string GIT_workingdir = helper::read_object_string_value_ascii(&d, "GIT", "workingdir");

		if (GIT_host == L"" || GIT_port == -1 || GIT_url == L"" || GIT_username == "" || GIT_password == "" || GIT_email == "" || GIT_workingdir == "") {

			std::wcout << "[DEXTER][" << PROTOCOL << "]" << " It appears something is wrong with the configuration file" << std::endl;
			libnet::finalize();
			return -1;
		}

		std::wcout << "[DEXTER]" << " Using " << PROTOCOL << " as transport method" << std::endl;

		libagent::test_git_over_ssh_protocol(GIT_host, GIT_port, GIT_url, GIT_username, GIT_password, GIT_email, GIT_workingdir, AES_PASSWORD, PoC_KEYWORD);
	}

	libnet::finalize();

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
