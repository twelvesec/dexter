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
#pragma comment (lib, "wininet.lib")
#include <WinInet.h>

namespace libftp {
	HINTERNET open(std::wstring uagent);
	HINTERNET connect(HINTERNET internet, std::wstring host, WORD port, std::wstring username, std::wstring password);
	bool set_current_dir(HINTERNET connection, std::wstring directory);
	bool write_file(HINTERNET connection, std::wstring filename, std::string data);
}
