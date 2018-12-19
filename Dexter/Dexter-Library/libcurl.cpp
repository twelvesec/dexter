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

#include "libcurl.h"

#define CURL_STATICLIB
#include <curl/curl.h>
#include "helper.h"

#define SimpleEmailHeaderLines	12

const char *_simpleEmailHeader[] = {
	"Date: %s\r\n",
	"To: %s (%s)\r\n",
	"From: %s (%s)\r\n",
	"Message-ID: <%s>\r\n",
	"Subject: %s\r\n",
	"MIME-Version: 1.0\r\n",
	"Content-Type: multipart/mixed; boundary=%s\r\n\r\n",
	"--%s\r\n",
	"Content-type: text/plain; charset=UTF-8\r\n",
	"Content-Transfer-Encoding: 7bit\r\n\r\n",
	"%s",
	"\r\n--%s--\r\n"
};

static std::string _buildDate(const char *format) {
	std::string date;
	char *_dateTime = 0;
	size_t _size = 0;
	char *result;

	if ((helper::get_timezone_offset(&_dateTime)) == false) {
		return "";
	}

	_size = strlen(format) + strlen(_dateTime);

	if ((result = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _size + 1)) == NULL) {
		HeapFree(GetProcessHeap(), 0, _dateTime);
		_dateTime = NULL;
		return "";
	}

	if (_snprintf_s(result, _size + 1, _TRUNCATE, format, _dateTime) == -1) {
		HeapFree(GetProcessHeap(), 0, _dateTime);
		_dateTime = NULL;
		HeapFree(GetProcessHeap(), 0, result);
		result = NULL;
		return "";
	}

	HeapFree(GetProcessHeap(), 0, _dateTime);
	_dateTime = NULL;

	date = std::string(result);

	HeapFree(GetProcessHeap(), 0, result);
	result = NULL;

	return date;
}

static std::string _buildToFrom(const char *format, const char *tofrom, const char *name) {
	size_t _size = 0;
	char *result;
	std::string tofromstr;

	_size = strlen(format) + strlen(tofrom) + strlen(name);

	if ((result = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _size + 1)) == NULL) {
		return "";
	}

	if (_snprintf_s(result, _size + 1, _TRUNCATE, format, tofrom, name) == -1) {
		HeapFree(GetProcessHeap(), 0, result);
		result = NULL;
		return "";
	}

	tofromstr = std::string(result);

	HeapFree(GetProcessHeap(), 0, result);
	result = NULL;

	return tofromstr;
}

static std::string _generateMessageID(const char *sender, SIZE_T senderLength) {

	GUID pGuiId;
	WCHAR sGuiId[64] = { 0 };
	WCHAR sTrimId[64] = { 0 };
	std::string messageid;

	int strFromGuiSize = 0;
	char *senderCopy = 0;
	int domainSize = 50;
	char domain[50] = { 0 };
	char *context = 0;
	char *tmp = 0;
	char *sTrimIdA = 0;
	size_t messageIDSize = 0;
	char *messageID;

	//copy sender email
	if ((senderCopy = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, senderLength + 1)) == NULL) {
		return "";
	}

	if (strncpy_s(senderCopy, senderLength + 1, sender, _TRUNCATE) != 0) {
		HeapFree(GetProcessHeap(), 0, senderCopy);
		senderCopy = NULL;
		return "";
	}

	//get first token
	if (helper::next_token(senderCopy, "@", &context) == NULL) {
		HeapFree(GetProcessHeap(), 0, senderCopy);
		senderCopy = NULL;
		return "";
	}

	//Get email domain
	if ((tmp = helper::next_token(NULL, "@", &context)) == NULL) {
		HeapFree(GetProcessHeap(), 0, senderCopy);
		senderCopy = NULL;
		return "";
	}

	if (strncpy_s(domain, domainSize, tmp, _TRUNCATE) != 0) {
		HeapFree(GetProcessHeap(), 0, senderCopy);
		senderCopy = NULL;
		return "";
	}

	HeapFree(GetProcessHeap(), 0, senderCopy);
	senderCopy = NULL;

	//Create a GUID, a unique 128-bit integer.
	if (CoCreateGuid(&pGuiId) != S_OK) {
		return "";
	}

	//Convert a globally unique identifier (GUID) into a string of printable characters.
	if ((strFromGuiSize = StringFromGUID2(pGuiId, sGuiId, _countof(sGuiId))) == 0) {
		return "";
	}

	//Remove { and } from generated GUID
	if (wmemmove_s(sTrimId, 64, sGuiId + 1, strFromGuiSize - 3) != 0) {
		return "";
	}

	sTrimId[strFromGuiSize - 3] = '\0';

	//Convert GUID to ascii
	sTrimIdA = helper::Wchar_To_Char(sTrimId, 64);
	if (sTrimIdA == NULL) {
		return "";
	}

	//messageID will store the final message-id value
	messageIDSize = strlen(sTrimIdA) + 1 + strlen(domain) + 1;

	if ((messageID = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, messageIDSize)) == NULL) {
		HeapFree(GetProcessHeap(), 0, sTrimIdA);
		sTrimIdA = NULL;
		return "";
	}

	//copy trimmed guid to messageid e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if (_snprintf_s(messageID, messageIDSize, _TRUNCATE, "%s", sTrimIdA) == -1) {
		HeapFree(GetProcessHeap(), 0, sTrimIdA);
		sTrimIdA = NULL;
		HeapFree(GetProcessHeap(), 0, messageID);
		messageID = NULL;
		return "";
	}

	//concat @ e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@
	if (_snprintf_s(messageID + strlen(sTrimIdA), messageIDSize - strlen(sTrimIdA), _TRUNCATE, "%s", "@") == -1) {
		HeapFree(GetProcessHeap(), 0, sTrimIdA);
		sTrimIdA = NULL;
		HeapFree(GetProcessHeap(), 0, messageID);
		messageID = NULL;
		return "";
	}

	//concat domain e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@example.com
	if (_snprintf_s(messageID + strlen(sTrimIdA) + 1, messageIDSize - strlen(sTrimIdA) - 1, _TRUNCATE, "%s", domain) == -1) {
		HeapFree(GetProcessHeap(), 0, sTrimIdA);
		sTrimIdA = NULL;
		HeapFree(GetProcessHeap(), 0, messageID);
		messageID = NULL;
		return "";
	}

	HeapFree(GetProcessHeap(), 0, sTrimIdA);
	sTrimIdA = NULL;

	messageid = std::string(messageID);

	HeapFree(GetProcessHeap(), 0, messageID);
	messageID = NULL;

	return messageid;
}

static std::string _buildMessageID(const char *format, const char *from) {

	size_t _size = 0;
	char *result;
	std::string msgid;

	if ((msgid = _generateMessageID(from, strlen(from))) == "") {
		return "";
	}

	_size = strlen(format) + msgid.length();

	if ((result = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _size + 1)) == NULL) {
		return "";
	}

	if (_snprintf_s(result, _size + 1, _TRUNCATE, format, msgid.c_str()) == -1) {
		HeapFree(GetProcessHeap(), 0, result);
		result = NULL;
		return "";
	}

	msgid = std::string(result);

	HeapFree(GetProcessHeap(), 0, result);
	result = NULL;

	return msgid;
}

static std::string _buildString(const char *format, const char *value) {

	size_t _size = 0;
	char *result;
	std::string str;

	_size = strlen(format) + strlen(value);

	if ((result = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _size + 1)) == NULL) {
		return "";
	}

	if (_snprintf_s(result, _size + 1, _TRUNCATE, format, value) == -1) {
		HeapFree(GetProcessHeap(), 0, result);
		result = NULL;
		return "";
	}

	str = std::string(result);

	HeapFree(GetProcessHeap(), 0, result);
	result = NULL;

	return str;
}

static std::string _buildString(const char *format, int value) {

	size_t _size = 0;
	char *result;
	std::string str;

	_size = strlen(format) * 2;

	if ((result = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _size + 1)) == NULL) {
		return "";
	}

	if (_snprintf_s(result, _size + 1, _TRUNCATE, format, value) == -1) {
		HeapFree(GetProcessHeap(), 0, result);
		result = NULL;
		return "";
	}

	str = std::string(result);

	HeapFree(GetProcessHeap(), 0, result);
	result = NULL;

	return str;
}

static std::string _buildMessage(std::string username, std::string name, std::string subject, std::string body) {
	std::string message;

	message = _buildDate(_simpleEmailHeader[0]);

	message += _buildToFrom(_simpleEmailHeader[1], username.c_str(), name.c_str());

	message += _buildToFrom(_simpleEmailHeader[2], username.c_str(), name.c_str());

	message += _buildMessageID(_simpleEmailHeader[3], username.c_str());

	message += _buildString(_simpleEmailHeader[4], subject.c_str());

	message += std::string(_simpleEmailHeader[5]);

	message += _buildString(_simpleEmailHeader[6], BOUNDARY);

	message += _buildString(_simpleEmailHeader[7], BOUNDARY);

	message += std::string(_simpleEmailHeader[8]);

	message += std::string(_simpleEmailHeader[9]);

	message += _buildString(_simpleEmailHeader[10], body.c_str());

	message += _buildString(_simpleEmailHeader[11], BOUNDARY);

	return message;
}

/*
static size_t _ftp_write_function_callback(void *buffer, size_t size, size_t nmemb, void *stream)
{
	struct FtpFile *out = (struct FtpFile *)stream;
	if (out && !out->stream) {
		fopen_s(&out->stream, out->filename, "wb");
		if (!out->stream)
			return -1;
	}
	return fwrite(buffer, size, nmemb, out->stream);
}
*/

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	char *ptr = (char*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, mem->memory, mem->size + realsize + 1);
	if (ptr == NULL) {
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

static size_t _ftp_read_function_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct WriteThis *upload = (struct WriteThis *)userp;
	size_t max = size * nmemb;

	if (max < 1)
		return 0;

	if (upload->sizeleft) {
		size_t copylen = max;
		if (copylen > upload->sizeleft)
			copylen = upload->sizeleft;
		memcpy(ptr, upload->readptr, copylen);
		upload->readptr += copylen;
		upload->sizeleft -= copylen;
		return copylen;
	}

	return 0;                          /* no more data left to deliver */
}

static size_t _read_function_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
	data_size *upload_ctx = (data_size *)userp;
	size_t dataLen = 0;

	if ((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
		return 0;
	}

	if (upload_ctx->size) {
		if (upload_ctx->size > MYSIZE) {
			dataLen = MYSIZE;
		}
		else {
			dataLen = upload_ctx->size;
		}

		memcpy(ptr, upload_ctx->data, dataLen);
		upload_ctx->data += dataLen;
		upload_ctx->size -= dataLen;

		return dataLen;
	}

	return 0;
}

//libcurl email write callback
static size_t _write_function_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	data_size *mem = (data_size *)userp;
	//char *tmp;

	if ((mem->data = (char*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, mem->data, mem->size + realsize + 1)) == NULL) {
		return 0;
	}

	//mem->data = tmp;
	memcpy(&(mem->data[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->data[mem->size] = '\0';

	return realsize;
}

static std::vector<int> _extractEmailsIds(const char *downloadData) {
	//char **splittedString = { 0 };
	size_t carriageReturnIndex = 0;
	char *data = 0;
	//size_t total = -1;
	int i = 0;
	//int splitted = 0;
	//int j = 0;
	std::vector<std::string> tokens;
	std::vector<int> ids;

	//remove carriage return
	carriageReturnIndex = strcspn(downloadData, "\r\n");
	if (carriageReturnIndex > 0 && ((data = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, carriageReturnIndex + 1)) != NULL)) {

		if (strncpy_s(data, carriageReturnIndex + 1, downloadData, carriageReturnIndex) == 0) {

			//split string to get email ids
			//if ((splittedString = helper::split_string(&splitted, data, (DWORD)carriageReturnIndex, " ")) != NULL) {
			tokens = helper::split_string(std::string(data), ' ');
			//if ((splitted = helper::split_string(data, (DWORD)carriageReturnIndex, " ", &splittedString)) != -1) {

			if (tokens.size() > 2) {
				//total = tokens.size() - 2;
				//get ids
					//ignore "* SEARCH"
				for (i = 2; i < tokens.size(); i++) {
					ids.push_back(atoi(tokens[i].c_str()));
				}
			}

		}

		HeapFree(GetProcessHeap(), 0, data);
		data = NULL;
	}

	return ids;
}

void libcurl::init(void) {
	curl_global_init(CURL_GLOBAL_ALL);
}

void libcurl::finalize(void) {
	curl_global_cleanup();
}

bool libcurl::send_email(std::string username, std::string password, std::string smtp, std::string name,
	std::string subject, std::string body, std::string uagent) {
	std::string message;
	CURL *curl;
	CURLcode res = CURLE_OK;
	struct curl_slist *recipients = NULL;
	data_size upload_ctx;
	bool success = false;

	message = _buildMessage(username, name, subject, body);

	upload_ctx.data = (char*)message.c_str();
	upload_ctx.size = message.length();

	if ((curl = curl_easy_init())) {
		curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
		curl_easy_setopt(curl, CURLOPT_URL, smtp.c_str());
		curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_MAIL_FROM, username.c_str());
		recipients = curl_slist_append(recipients, username.c_str());
		curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, _read_function_callback);
		curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); //debug, turn it off on production
		curl_easy_setopt(curl, CURLOPT_USERAGENT, uagent.c_str());

		if ((res = curl_easy_perform(curl)) == CURLE_OK)
		{
			success = true;
		}

		curl_slist_free_all(recipients);
		curl_easy_cleanup(curl);
	}

	return success;
}

std::vector<int> libcurl::get_emails_ids(std::string username, std::string password, std::string imap, std::string command, std::string uagent) {

	CURL *curl;
	CURLcode res = CURLE_OK;
	data_size download_ctx;
	std::vector<int> ids;

	download_ctx.data = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1);
	download_ctx.size = 0;

	if ((curl = curl_easy_init())) {
		curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
		curl_easy_setopt(curl, CURLOPT_URL, imap.c_str());
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, command.c_str());
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); //debug, turn it off on production
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_function_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &download_ctx);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, uagent.c_str());

		if ((res = curl_easy_perform(curl)) == CURLE_OK)
		{
			ids = _extractEmailsIds(download_ctx.data);
		}

		curl_easy_cleanup(curl);
	}

	return ids;
}

bool libcurl::receive_email(MimeMessage **mm, int uid, std::string imap_inbox_obj, std::string username, std::string password, std::string uagent) {
	bool success = false;

	CURL *curl;
	CURLcode res = CURLE_OK;
	data_size download_ctx;

	download_ctx.data = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1);
	download_ctx.size = 0;

	std::string url = _buildString(imap_inbox_obj.c_str(), uid);

	if ((curl = curl_easy_init())) {
		curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); //debug, turn it off on production
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_function_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &download_ctx);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, uagent.c_str());

		if ((res = curl_easy_perform(curl)) == CURLE_OK)
		{
			if ((*mm = (MimeMessage*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MimeMessage))) != NULL) {
				libmime::parse_mime(*mm, download_ctx.data, download_ctx.size);
				success = true;
			}
		}

		curl_easy_cleanup(curl);

		HeapFree(GetProcessHeap(), 0, download_ctx.data);
		download_ctx.data = NULL;
	}

	return success;
}

bool libcurl::ftps_upload(std::string directory, std::string filename, std::string username, std::string password, std::string host, WORD port, std::string uagent, std::string data) {

	CURL *curl;
	CURLcode res = CURLE_OK;
	bool success = false;
	struct WriteThis upload;

	upload.readptr = data.c_str();
	upload.sizeleft = data.length();

	if ((curl = curl_easy_init())) {

		std::string url = "ftp://" + host + directory + "/" + filename;
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, _ftp_read_function_callback);
		curl_easy_setopt(curl, CURLOPT_READDATA, &upload);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); //debug, turn it off on production
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)upload.sizeleft);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, uagent.c_str());
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_PORT, port);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);

		if ((res = curl_easy_perform(curl)) == CURLE_OK)
		{
			success = true;
		}

		curl_easy_cleanup(curl);
	}

	return success;
}

std::string libcurl::ftps_download(std::string directory, std::string filename, std::string username, std::string password, std::string host, WORD port, std::string uagent) {

	CURL *curl;
	CURLcode res = CURLE_OK;
	struct MemoryStruct chunk;
	std::string data;

	chunk.memory = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1);
	chunk.size = 0;

	if ((curl = curl_easy_init())) {

		std::string url = "ftp://" + host + directory + "/" + filename;
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); //debug, turn it off on production
		curl_easy_setopt(curl, CURLOPT_USERAGENT, uagent.c_str());
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_PORT, port);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);

		if ((res = curl_easy_perform(curl)) == CURLE_OK)
		{
			data = std::string(chunk.memory);
		}

		curl_easy_cleanup(curl);
		HeapFree(GetProcessHeap(), 0, chunk.memory);
		chunk.memory = NULL;
	}

	return data;
}
