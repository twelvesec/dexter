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

namespace libreporter {
	void test_http_protocol(std::wstring host, WORD port, std::wstring token_uri_method, std::wstring clients_uri_method, std::wstring tokenuri,
		std::wstring clients_uri, std::set<std::wstring> uagents, WORD clientid, std::string secret, std::string username,
		std::string password, std::string aespassword, std::string PoC_KEYWORD, bool IGNORE_CERT_UNKNOWN_CA, bool IGNORE_CERT_DATE_INVALID,
		bool TLS_CONNECTION);
	void test_gmail_protocol(std::string gmail_imap, std::string gmail_imap_inbox_obj, std::string gmail_username, std::string gmail_password, std::string gmail_name,
		std::set<std::wstring> uagents, std::string aespassword, std::string PoC_KEYWORD);
	void test_ftp_protocol(std::wstring host, WORD port, std::wstring username, std::wstring password, std::set<std::wstring> uagents, std::string aespassword,
		std::wstring directory, std::string PoC_KEYWORD);
	void test_ftps_protocol(std::string host, WORD port, std::string username, std::string password, std::set<std::wstring> uagents, std::string aespassword,
		std::string directory, std::string PoC_KEYWORD, bool ignore_unknown_ca);
	void test_smtp_protocol(std::string imap, std::string imap_inbox_obj, std::string username, std::string password, std::string name,
		std::set<std::wstring> uagents, std::string aespassword, std::string PoC_KEYWORD, bool OverTls, bool ignore_unknown_ca);
	void test_git_protocol(std::string url, std::string username, std::string password, std::string folder, std::string aespassword);
}
