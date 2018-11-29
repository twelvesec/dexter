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

#include "libmime.h"
#include "helper.h"

bool libmime::parse_mime(MimeMessage *msg, const char *raw_data, size_t rawDataSize) {
	//char **splittedString = { 0 };
	//int splitted = 0;
	int i = 0;
	size_t equalIndex = 0;
	size_t carriageIndex = 0;
	char boundary[256] = "--";
	char *tmp = 0;
	std::vector<std::string> data;

	//if ((splitted = helper::split_string(raw_data, (DWORD)rawDataSize, "\n", &splittedString)) != -1) {
	data = helper::split_string(raw_data, '\n');
	for (i = 0; i < data.size(); i++) {

		//extract boundary value
		if (strstr(data[i].c_str(), "boundary") != NULL) {
			equalIndex = strcspn(data[i].c_str(), "=");
			carriageIndex = strcspn(data[i].c_str(), "\r");
			if (strncat_s(boundary, sizeof(boundary), data[i].c_str() + equalIndex + 1, carriageIndex - equalIndex - 1) == S_FALSE) {
				break;
			}
		}

		//body message begins
		if (strstr(data[i].c_str(), "Content-type: text/plain; charset=UTF-8") != NULL) {

			//ignore next empty line
			i += 2;
			//read till boundary
			while (strstr(data[i].c_str(), boundary) == NULL && i < data.size()) {

				//ignore empty lines
				if (strcmp(data[i].c_str(), "\r") != 0) {

					if (msg->body == NULL)
					{
						if ((msg->body = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, strlen(data[i].c_str()))) == NULL) {
							break;
						}

						carriageIndex = strcspn(data[i].c_str(), "\r");
						msg->length = (unsigned int)carriageIndex;

						if (strncpy_s(msg->body, strlen(data[i].c_str()), data[i].c_str(), carriageIndex) == EINVAL) {
							break;
						}
					}
					else
					{
						if ((tmp = (char*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, msg->body, strlen(msg->body) + strlen(data[i].c_str()))) == NULL) {
							break;
						}

						msg->body = tmp;
						carriageIndex = strcspn(data[i].c_str(), "\r");
						msg->length += (unsigned int)carriageIndex;

						if (strncat_s(msg->body, strlen(msg->body) + strlen(data[i].c_str()), data[i].c_str(), carriageIndex) == EINVAL) {
							break;
						}
					}
				}
				i++;
			}
			//stop reading
			break;
		}
	}
	return true;
}
