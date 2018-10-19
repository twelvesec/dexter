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

#include <string>
#include <set>
#include "rapidjson/document.h"

namespace helper {
	std::string read_config_string_value(rapidjson::Document *doc, const char *name, const char *config);
	int read_config_int_value(rapidjson::Document *doc, const char *name, const char *config);
	int random_number(int min, int max);
	std::string pick_random_useragent_fromfile(std::set<std::string> useragents);
	std::set<std::string> load_useragent_strings(std::wstring filename);
	std::string load_json_file(std::wstring filename);
}
