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

#include "libencode.h"

//#include <wininet.h>
#pragma comment (lib, "Shlwapi.lib")
#include <shlwapi.h>

#pragma comment(lib, "Crypt32.lib")
#include <wincrypt.h>


std::string libencode::base64_encode(std::string plaintext) {
	std::string encodedtext;
	DWORD size = 0;
	char *dest;

	if (CryptBinaryToStringA((BYTE*)plaintext.c_str(), (DWORD)plaintext.length(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size) == FALSE) {
		return "";
	}

	if ((dest = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1)) == NULL) {
		return "";
	}

	if (CryptBinaryToStringA((BYTE*)plaintext.c_str(), (DWORD)plaintext.length(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, dest, &size) == FALSE)
	{
		HeapFree(GetProcessHeap(), 0, dest);
		dest = NULL;
		return "";
	}

	dest[size] = 0;
	encodedtext = std::string(dest);
	HeapFree(GetProcessHeap(), 0, dest);
	dest = NULL;

	return encodedtext;
}

std::string libencode::base64_encode(BYTE *plaintext, DWORD plainTextLength) {
	std::string encodedtext;
	DWORD size = 0;
	char *dest;

	if (CryptBinaryToStringA(plaintext, plainTextLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size) == FALSE) {
		return "";
	}

	if ((dest = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1)) == NULL) {
		return "";
	}

	if (CryptBinaryToStringA(plaintext, plainTextLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, dest, &size) == FALSE)
	{
		HeapFree(GetProcessHeap(), 0, dest);
		dest = NULL;
		return "";
	}

	dest[size] = 0;
	encodedtext = std::string(dest);
	HeapFree(GetProcessHeap(), 0, dest);
	dest = NULL;

	return encodedtext;
}

std::string libencode::base64_decode(std::string encodedtext) {
	std::string plaintext;
	DWORD size = 0;
	BYTE *dest;

	if (CryptStringToBinaryA(encodedtext.c_str(), (DWORD)encodedtext.length(), CRYPT_STRING_BASE64, NULL, &size, NULL, NULL) == FALSE) {
		return "";
	}

	if ((dest = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size + 1) * sizeof(BYTE))) == NULL) {
		return "";
	}

	if (CryptStringToBinaryA(encodedtext.c_str(), (DWORD)encodedtext.length(), CRYPT_STRING_BASE64, dest, &size, NULL, NULL) == FALSE) {
		HeapFree(GetProcessHeap(), 0, dest);
		dest = NULL;
		return "";
	}

	dest[size] = 0;
	plaintext = std::string((char*)dest);
	HeapFree(GetProcessHeap(), 0, dest);
	dest = NULL;

	return plaintext;
}

DWORD libencode::base64_decode(BYTE **plaintext, std::string encodedtext) {
	DWORD size = 0;

	if (CryptStringToBinaryA(encodedtext.c_str(), (DWORD)encodedtext.length(), CRYPT_STRING_BASE64, NULL, &size, NULL, NULL) == FALSE) {
		return 0;
	}

	if ((*plaintext = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size + 1) * sizeof(BYTE))) == NULL) {
		return 0;
	}

	if (CryptStringToBinaryA(encodedtext.c_str(), (DWORD)encodedtext.length(), CRYPT_STRING_BASE64, *plaintext, &size, NULL, NULL) == FALSE) {
		HeapFree(GetProcessHeap(), 0, *plaintext);
		*plaintext = NULL;
		return 0;
	}

	(*plaintext)[size] = 0;

	return size;
}

std::string libencode::url_encode(std::string uri) {
	std::string encoded;
	DWORD len = (DWORD)uri.length();
	char *tmp;
	HRESULT result;

	if ((tmp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1)) == NULL) {
		return "";
	}

	if ((result = UrlEscapeA(uri.c_str(), tmp, &len, URL_ESCAPE_SEGMENT_ONLY | URL_ESCAPE_PERCENT)) != S_OK && result != E_POINTER) {
		HeapFree(GetProcessHeap(), 0, tmp);
		tmp = NULL;
		return "";
	}

	HeapFree(GetProcessHeap(), 0, tmp);
	tmp = NULL;

	if ((tmp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len)) == NULL) {
		return "";
	}

	if ((result = UrlEscapeA(uri.c_str(), tmp, &len, URL_ESCAPE_SEGMENT_ONLY | URL_ESCAPE_PERCENT)) != S_OK && result != E_POINTER) {
		HeapFree(GetProcessHeap(), 0, tmp);
		tmp = NULL;
		return "";
	}

	tmp[len] = 0;
	encoded = std::string(tmp);
	HeapFree(GetProcessHeap(), 0, tmp);
	tmp = NULL;

	std::string tosearch = "+";
	std::string replace = "%2b";
	size_t pos = encoded.find(tosearch);
	while (pos != std::string::npos)
	{
		encoded.replace(pos, tosearch.size(), replace);
		pos = encoded.find(tosearch, pos + tosearch.size());
	}

	return encoded;
}

std::string libencode::url_decode(std::string uri) {
	std::string decoded;
	DWORD len = (DWORD)uri.length();
	char *tmp;
	HRESULT result;

	std::string tosearch = "%2b";
	std::string replace = "+";
	size_t pos = uri.find(tosearch);
	while (pos != std::string::npos)
	{
		uri.replace(pos, tosearch.size(), replace);
		pos = uri.find(tosearch, pos + tosearch.size());
	}

	if ((tmp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1)) == NULL) {
		return "";
	}

	if ((result = UrlUnescapeA((char*)uri.c_str(), tmp, &len, 0)) != S_OK && result != E_POINTER) {
		HeapFree(GetProcessHeap(), 0, tmp);
		tmp = NULL;
		return "";
	}

	HeapFree(GetProcessHeap(), 0, tmp);
	tmp = NULL;

	if ((tmp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1)) == NULL) {
		return "";
	}

	if ((result = UrlUnescapeA((char*)uri.c_str(), tmp, &len, 0)) != S_OK && result != E_POINTER) {
		HeapFree(GetProcessHeap(), 0, tmp);
		tmp = NULL;
		return "";
	}

	tmp[len] = 0;
	decoded = std::string(tmp);
	HeapFree(GetProcessHeap(), 0, tmp);
	tmp = NULL;

	return decoded;
}
