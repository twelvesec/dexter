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

#include "helper.h"

#include <algorithm>
#include <time.h>
#include <fstream>
#include <string>
#include <sstream>

#pragma comment (lib, "Shlwapi.lib")
#include <Shlwapi.h>

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

std::string helper::read_string_value_ascii(rapidjson::Document *doc, const char *name) {
	if (doc->IsNull() == true) return "";

	if (doc->HasMember(name) && (*doc)[name].IsString()) {
		std::string val((*doc)[name].GetString());
		return val;
	}
	return "";
}

std::wstring helper::read_string_value(rapidjson::Document *doc, const char *name) {
	if (doc->IsNull() == true) return L"";

	if (doc->HasMember(name) && (*doc)[name].IsString()) {
		std::string val((*doc)[name].GetString());
		return std::wstring(val.begin(), val.end());
	}

	return L"";
}

bool helper::read_bool_value(rapidjson::Document *doc, const char *name) {
	if (doc->IsNull() == true) return false;

	if (doc->HasMember(name) && (*doc)[name].IsBool()) {
		bool val((*doc)[name].GetBool());
		return val;
	}

	return false;
}

std::wstring helper::read_object_string_value(rapidjson::Document *doc, const char *name, const char *config) {
	if (doc->IsNull() == true) return L"";

	if (doc->HasMember(name) && (*doc)[name].IsObject()) {
		for (rapidjson::Value::ConstMemberIterator itr = (*doc)[name].MemberBegin(); itr != (*doc)[name].MemberEnd(); ++itr) {
			if (itr->name != NULL) {
				std::string val(itr->name.GetString());
				if (val == config && itr->value != NULL) {
					std::string s = itr->value.GetString();
					return std::wstring(s.begin(), s.end());
				}
			}
		}
	}

	return L"";
}

std::string helper::read_object_string_value_ascii(rapidjson::Document *doc, const char *name, const char *config) {
	if (doc->IsNull() == true) return "";

	if (doc->HasMember(name) && (*doc)[name].IsObject()) {
		for (rapidjson::Value::ConstMemberIterator itr = (*doc)[name].MemberBegin(); itr != (*doc)[name].MemberEnd(); ++itr) {
			if (itr->name != NULL) {
				std::string val(itr->name.GetString());
				if (val == config && itr->value != NULL) {
					return itr->value.GetString();
				}
			}
		}
	}

	return "";
}

WORD helper::read_object_word_value(rapidjson::Document *doc, const char *name, const char *config) {
	if (doc->IsNull() == true) return -1;

	if (doc->HasMember(name) && (*doc)[name].IsObject()) {
		for (rapidjson::Value::ConstMemberIterator itr = (*doc)[name].MemberBegin(); itr != (*doc)[name].MemberEnd(); ++itr) {
			if (itr->name != NULL) {
				std::string val(itr->name.GetString());
				if (val == config && itr->value != NULL) {
					return itr->value.GetInt();
				}
			}
		}
	}

	return -1;
}

int helper::random_number(int min, int max) {
	if (min < 0 || max < 0 || max > RAND_MAX) return 0;

	time_t seconds;
	time(&seconds);

	if (!seconds) {
		return 0;
	}

	srand((unsigned int)seconds);

	return rand() % (max - min + 1) + min;
}

std::wstring helper::pick_random_useragent_fromfile(std::set<std::wstring> useragents) {
	std::set<std::wstring>::const_iterator it(useragents.begin());
	int index = random_number(0, (int)useragents.size() - 1);
	advance(it, index);

	return *it;
}

std::set<std::wstring> helper::load_useragent_strings(std::wstring filename) {
	std::wstring line;
	std::set<std::wstring> useragents;
	std::wifstream ifsuagen(filename);

	if (!ifsuagen) {
		return useragents;
	}

	while (std::getline(ifsuagen, line)) {
		useragents.insert(line);
	}

	return useragents;
}

std::string helper::load_json_file(std::wstring filename) {

	if (!PathFileExistsW(filename.c_str())) {
		return "";
	}

	std::ifstream ifscfg(filename);

	if (!ifscfg) {
		return "";
	}

	std::string config_file_content((std::istreambuf_iterator<char>(ifscfg)),
		(std::istreambuf_iterator<char>()));

	return config_file_content;
}

char* helper::next_token(char *strToken, const char *strDelimit, char **context) {
	return strtok_s(strToken, strDelimit, context);
}

std::vector<std::string> helper::split_string(std::string str, char delimeter) {
	std::vector<std::string> tokens;
	std::stringstream check1(str);

	std::string intermediate;

	while (std::getline(check1, intermediate, delimeter)) {
		tokens.push_back(intermediate);
	}

	return tokens;
}

bool helper::get_timezone_offset(char **datetime) {
	struct tm lcl;
	struct tm gmt;

	if (((*datetime) = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 50)) == NULL) {
		return false;
	}

	time_t now = time(NULL);

	if (!now) return false;

	localtime_s(&lcl, &now);
	time_t local = mktime(&lcl);

	if (!local) return false;

	gmtime_s(&gmt, &now);
	time_t utc = mktime(&gmt);

	if (!utc) return false;

	//Mon, 29 Nov 2010 21:54:29 +1100
	if (strftime(*datetime, 50, "%a, %d %b %Y %H:%M:%S %z", &gmt) == 0) {
		return false;
	}

	return true;
}

char* helper::Wchar_To_Char(const wchar_t *src, int slen) {
	if (src == NULL || slen <= 0)return NULL;

	int len = 0;
	char *dest = 0;

	//Maps a UTF-16 (wide character) string to a new character string. 
	//The new character string is not necessarily from a multibyte character set. 
	//return the required buffer size
	if ((len = WideCharToMultiByte(CP_ACP, 0, src, slen, NULL, 0, NULL, NULL)) == 0) {
		return NULL;
	}

	if ((dest = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1)) == NULL) {
		return NULL;
	}

	//convert
	if (WideCharToMultiByte(CP_ACP, 0, src, slen, dest, len, NULL, NULL) == 0) {
		HeapFree(GetProcessHeap(), 0, dest);
		dest = NULL;
		return NULL;
	}

	dest[len] = '\0';

	return dest;
}

std::string helper::GetLastErrorStringA(DWORD error) {

	char *lastErrorString = nullptr;
	DWORD size = 0;

	if (error == 0) {
		return "";
	}

	if ((size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&lastErrorString, 0, NULL)) == 0) {

		return "";
	}

	std::string message(lastErrorString, size);
	message.erase(std::remove(message.begin(), message.end(), '\n'), message.end());
	message.erase(std::remove(message.begin(), message.end(), '\n'), message.end());

	LocalFree(lastErrorString);

	return message;
}

std::string helper::GetLastErrorStringA(void) {

	return GetLastErrorStringA(GetLastError());
}

std::wstring helper::GetLastErrorStringW(DWORD error) {

	wchar_t *lastErrorString = nullptr;
	DWORD size = 0;

	if (error == 0) {
		return L"";
	}

	if ((size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (wchar_t*)&lastErrorString, 0, NULL)) == 0) {

		return L"";
	}

	std::wstring message(lastErrorString, size);
	message.erase(std::remove(message.begin(), message.end(), '\r'), message.end());
	message.erase(std::remove(message.begin(), message.end(), '\n'), message.end());

	LocalFree(lastErrorString);

	return message;
}

std::wstring helper::GetLastErrorStringW(void) {

	return GetLastErrorStringW(GetLastError());
}
