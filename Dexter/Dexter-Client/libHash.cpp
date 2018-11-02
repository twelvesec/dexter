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

#include "libHash.h"

#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>

std::string libHash::sha256(std::string input) {
	std::string hash;
	sha256_context ctx;
	BYTE tmp[SHA256_HASH_SIZE];
	DWORD size = SHA256_HASH_SIZE;
	char part[10] = { 0 };
	int outputSize = (SHA256_HASH_SIZE * 2) + 1;
	char *str;

	if (CryptAcquireContext(&ctx.hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == FALSE) {//CRYPT_VERIFYCONTEXT
		return "";
	}

	if (CryptCreateHash(ctx.hCryptProv, CALG_SHA_256, 0, 0, &ctx.hHash) == FALSE)
	{
		CryptReleaseContext(ctx.hCryptProv, 0);
		ctx.hCryptProv = 0;
		return "";
	}

	if (CryptHashData(ctx.hHash, (BYTE*)input.c_str(), (DWORD)input.length(), 0) == FALSE)
	{
		CryptReleaseContext(ctx.hCryptProv, 0);
		ctx.hCryptProv = 0;
		CryptDestroyHash(ctx.hHash);
		ctx.hHash = 0;
		return "";
	}

	if (CryptGetHashParam(ctx.hHash, HP_HASHVAL, tmp, &size, 0) == FALSE)
	{
		CryptReleaseContext(ctx.hCryptProv, 0);
		ctx.hCryptProv = 0;
		CryptDestroyHash(ctx.hHash);
		ctx.hHash = 0;
		return "";
	}

	CryptReleaseContext(ctx.hCryptProv, 0);
	ctx.hCryptProv = 0;
	CryptDestroyHash(ctx.hHash);
	ctx.hHash = 0;

	if ((str = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outputSize)) == NULL) {
		return "";
	}

	for (int i = 0; i < SHA256_HASH_SIZE; i++)
	{
		if (_snprintf_s(part, 10, _TRUNCATE, "%.2x", tmp[i]) == -1) {//%02x
			HeapFree(GetProcessHeap(), 0, str);
			str = NULL;
			return "";
		}

		if (strncat_s(str, outputSize, part, _TRUNCATE) != 0) {
			HeapFree(GetProcessHeap(), 0, str);
			str = NULL;
			return "";
		}
	}

	hash = std::string(str);
	HeapFree(GetProcessHeap(), 0, str);
	str = NULL;

	return hash;
}
