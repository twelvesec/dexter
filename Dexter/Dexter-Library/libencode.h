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

#include <windows.h>
#include <string>


namespace libencode {
	std::string base64_encode(std::string plaintext);
	std::string base64_encode(BYTE *plaintext, DWORD plainTextLength);
	std::string base64_decode(std::string encodedtext);
	DWORD base64_decode(BYTE **plaintext, std::string encodedtext);
	std::string url_encode(std::string uri);
	std::string url_decode(std::string uri);
}
