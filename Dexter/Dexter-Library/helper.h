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

#pragma once

#include <Windows.h>
#include <string>
#include <set>
#include "rapidjson/document.h"
#include <vector>

namespace helper {
	bool read_bool_value(rapidjson::Document *doc, const char *name);
	std::string read_string_value_ascii(rapidjson::Document *doc, const char *name);
	std::wstring read_string_value(rapidjson::Document *doc, const char *name);
	std::wstring read_object_string_value(rapidjson::Document *doc, const char *name, const char *config);
	std::string read_object_string_value_ascii(rapidjson::Document *doc, const char *name, const char *config);
	WORD read_object_word_value(rapidjson::Document *doc, const char *name, const char *config);
	int random_number(int min, int max);
	std::wstring pick_random_useragent_fromfile(std::set<std::wstring> useragents);
	std::set<std::wstring> load_useragent_strings(std::wstring filename);
	std::string load_json_file(std::wstring filename);
	char* next_token(char *strToken, const char *strDelimit, char **context);
	bool get_timezone_offset(char **datetime);
	char* Wchar_To_Char(const wchar_t *src, int slen);
	std::vector<std::string> split_string(std::string str, char delimeter);
	std::string GetLastErrorStringA(void);
	std::string GetLastErrorStringA(DWORD error);
	std::wstring GetLastErrorStringW(void);
	std::wstring GetLastErrorStringW(DWORD error);
}
