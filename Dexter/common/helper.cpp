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

std::string helper::read_config_string_value(rapidjson::Document *doc, const char *name, const char *config) {
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

int helper::read_config_int_value(rapidjson::Document *doc, const char *name, const char *config) {
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

std::string helper::pick_random_useragent_fromfile(std::set<std::string> useragents) {
	std::set<std::string>::const_iterator it(useragents.begin());
	int index = random_number(0, (int)useragents.size() - 1);
	advance(it, index);
	return *it;
}

std::set<std::string> helper::load_useragent_strings(std::wstring filename) {
	std::string line;
	std::set<std::string> useragents;
	std::ifstream ifsuagen(filename);
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
