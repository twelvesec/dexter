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

#include "libmime.h"
#include <Windows.h>
#include <string>
#include <vector>

#define BOUNDARY	"EEmmaaiill__BBoouunnddaarryy"

#define MYSIZE 4096

typedef struct {
	char *data;
	size_t size;
}data_size;

struct WriteThis {
	const char *readptr;
	size_t sizeleft;
};

namespace libcurl {
	void init(void);
	void finalize(void);
	bool send_email(std::string username, std::string password, std::string smtp, std::string name,
		std::string subject, std::string body, std::string uagent);
	std::vector<int> get_emails_ids(std::string username, std::string password, std::string imap, std::string command, std::string uagent);
	bool receive_email(MimeMessage **mm, int uid, std::string imap_inbox_obj, std::string username, std::string password, std::string uagent);
	bool ftps_upload(std::string directory, std::string filename, std::string username, std::string password, std::string host, WORD port, std::string uagent, std::string data);
}
