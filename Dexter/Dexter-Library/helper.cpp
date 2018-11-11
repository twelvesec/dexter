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

#pragma comment (lib, "Shlwapi.lib")
#include <Shlwapi.h>

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

std::string helper::read_string_value_ascii(rapidjson::Document *doc, const char *name) {
	if (doc->HasMember(name) && (*doc)[name].IsString()) {
		std::string val((*doc)[name].GetString());
		return val;
	}
	return "";
}

std::wstring helper::read_string_value(rapidjson::Document *doc, const char *name) {
	if (doc->HasMember(name) && (*doc)[name].IsString()) {
		std::string val((*doc)[name].GetString());
		return std::wstring(val.begin(), val.end());
	}
	return L"";
}

bool helper::read_bool_value(rapidjson::Document *doc, const char *name) {
	if (doc->HasMember(name) && (*doc)[name].IsBool()) {
		bool val((*doc)[name].GetBool());
		return val;
	}
	return false;
}

std::wstring helper::read_object_string_value(rapidjson::Document *doc, const char *name, const char *config) {
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

char* helper::NextToken(char *strToken, const char *strDelimit, char **context) {
	return strtok_s(strToken, strDelimit, context);
}

int helper::SplitString(const char *str, unsigned long size, const char *delim, char ***data) {
	char *token = 0;
	char *strCopy = 0;
	char *next_token = 0;
	int i = 0;
	int count = 0;

	if ((strCopy = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1)) == NULL) {
		return -1;
	}

	if (strncpy_s(strCopy, size + 1, str, _TRUNCATE) != 0) {
		HeapFree(GetProcessHeap(), 0, strCopy);
		strCopy = NULL;
		return -1;
	}

	//count tokens
	token = NextToken(strCopy, delim, &next_token);
	if (token == NULL) {
		HeapFree(GetProcessHeap(), 0, strCopy);
		strCopy = NULL;
		return -1;
	}

	while (token != NULL) {
		token = NextToken(NULL, delim, &next_token);
		count++;
	}

	HeapFree(GetProcessHeap(), 0, strCopy);
	strCopy = NULL;

	if ((strCopy = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1)) == NULL) {
		return -1;
	}

	if (strncpy_s(strCopy, size + 1, str, _TRUNCATE) != 0) {
		HeapFree(GetProcessHeap(), 0, strCopy);
		strCopy = NULL;
		return -1;
	}

	//get data
	if ((*data = (char**)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, count * sizeof(char*))) == NULL) {
		HeapFree(GetProcessHeap(), 0, strCopy);
		strCopy = NULL;
		return -1;
	}

	token = NextToken(strCopy, delim, &next_token);
	if (token == NULL) {
		HeapFree(GetProcessHeap(), 0, strCopy);
		strCopy = NULL;
		return -1;
	}

	while (token != NULL) {
		if (((*data)[i] = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, strlen(token) + 1)) == NULL) {
			break;
		}

		if (strncpy_s((*data)[i], strlen(token) + 1, token, _TRUNCATE) != 0) {
			HeapFree(GetProcessHeap(), 0, strCopy);
			data[i] = NULL;
			break;
		}

		i++;
		token = NextToken(NULL, delim, &next_token);
	}

	HeapFree(GetProcessHeap(), 0, strCopy);
	strCopy = NULL;

	return count;
}
