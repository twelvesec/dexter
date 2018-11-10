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

#define WIN_S03			0x0502
#define WIN_S08			0x0600
#define WIN_S08R2		0x0601
#define WIN_S12			0x0602
#define WIN_S12R2		0x0603
#define WIN_S16			0x0A00

namespace libsysteminfo {
	std::string get_computer_name(void);
	std::string get_username(void);
	std::string get_os_version(void);
	std::string get_active_netface_ip(void);
	std::string get_active_netface_mac(void);
}
