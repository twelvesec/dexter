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
#include <string>
#include <fstream>

#pragma comment (lib, "Shlwapi.lib")
#include <Shlwapi.h>

#include "libreporter.h"
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
	std::cout << "-----------------------------------------------------------------" << std::endl;
	std::cout << "  Dexter reporter v." << VERSION << " - Data EXfiltration TestER" << std::endl;
	std::cout << "-----------------------------------------------------------------" << std::endl << std::endl;

	PargeArgs(argc, argv);

	rapidjson::Document d;
	std::string config_file_content = helper::load_json_file(CONFIG_FILE);
	d.Parse(config_file_content.c_str());

	std::string HTTP_host = helper::read_config_string_value(&d, "HTTP", "host");
	int HTTP_port = helper::read_config_int_value(&d, "HTTP", "port");
	std::string HTTPs_host = helper::read_config_string_value(&d, "HTTPS", "host");
	int HTTPs_port = helper::read_config_int_value(&d, "HTTPS", "port");

	std::set<std::string> useragents = helper::load_useragent_strings(USER_AGENTS);

	// HTTP

	std::cout << "----------------------------------" << std::endl;
	std::cout << "  Checking HTTP as transport method" << std::endl;
	std::cout << "----------------------------------" << std::endl << std::endl;

	std::string useragent = helper::pick_random_useragent_fromfile(useragents);
	std::cout << "[HTTP] " << "User-Agent: " << useragent << std::endl;
	libreporter::test_http_protocol(HTTP_host, HTTP_port, useragent);

	std::cout << "-------------------------------------------" << std::endl << std::endl;

	// HTTPS

	std::cout << "----------------------------------" << std::endl;
	std::cout << "  Checking HTTPs as transport method" << std::endl;
	std::cout << "----------------------------------" << std::endl << std::endl;

	useragent = helper::pick_random_useragent_fromfile(useragents);
	std::cout << "[HTTP] " << "User-Agent: " << useragent << std::endl;
	libreporter::test_https_protocol(HTTPs_host, HTTPs_port, useragent);

	std::cout << "-------------------------------------------" << std::endl << std::endl;

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
