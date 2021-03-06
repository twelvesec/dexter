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
#include <vector>
#include <git2.h>

namespace libgit {
	void init(void);
	void finalize(void);
	bool add_and_commit(std::string username, std::string password, std::string email, std::string url, std::string folder, std::string data);
	std::vector<std::string> commit_messages(std::string username, std::string password, std::string url, std::string folder);
	bool clone_or_pull(git_repository **repo, git_remote **remote, char *username, char *password, std::string url, std::string folder);
}
