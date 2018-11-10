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

#include "libcrypt.h"
#include "libencode.h"

static bool derive_key_from_password(std::string password, HCRYPTKEY *key, HCRYPTPROV *hCryptProv) {
	HCRYPTHASH hHash = 0;
	bool success = true;

	if (success && CryptAcquireContext(hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == FALSE) {
		success = false;
	}

	if (success && CryptCreateHash(*hCryptProv, CALG_SHA_256, 0, 0, &hHash) == FALSE) {
		success = false;
	}

	if (success && CryptHashData(hHash, (BYTE*)password.c_str(), (DWORD)password.length(), 0) == FALSE) {
		success = false;
	}

	if (success && CryptDeriveKey(*hCryptProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, key) == FALSE) {
		success = false;
	}

	if (hHash) {
		CryptDestroyHash(hHash);
		hHash = 0;
	}

	return success;
}

std::string libcrypt::encrypt(std::string password, std::string plaintext) {
	std::string ciphertext;
	DWORD ciphersize = 0;
	DWORD ciphertempsize = 0;
	BYTE *cipher = 0;
	BYTE *ivandcipher = 0;
	DWORD ivandciphersize = 0;
	HCRYPTKEY key = 0;
	HCRYPTPROV hCryptProv = 0;
	DWORD mode = CRYPT_MODE_CBC;
	DWORD padding = PKCS5_PADDING;
	DWORD blocksize = 0, blocksizelen = sizeof(DWORD);
	BYTE *iv = 0;
	bool success = true;

	if (success && derive_key_from_password(password, &key, &hCryptProv) == false) {
		success = false;
	}

	if (success && CryptSetKeyParam(key, KP_MODE, (BYTE*)&mode, 0) == FALSE) {
		success = false;
	}

	if (success && CryptSetKeyParam(key, KP_PADDING, (BYTE*)&padding, 0) == FALSE) {
		success = false;
	}

	if (success && CryptGetKeyParam(key, KP_BLOCKLEN, (BYTE*)&blocksize, &blocksizelen, 0) == FALSE) {
		success = false;
	}

	blocksize /= 8;

	if (success && (iv = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, blocksize * sizeof(BYTE))) == NULL) {
		success = false;
	}

	if (success && CryptGenRandom(hCryptProv, blocksize, iv) == FALSE) {
		success = false;
	}

	if (success && CryptSetKeyParam(key, KP_IV, iv, 0) == FALSE) {
		success = false;
	}

	ciphersize = (DWORD)plaintext.length();

	if (success && CryptEncrypt(key, 0, TRUE, 0, NULL, &ciphersize, 0) == FALSE) {
		success = false;
	}

	if (success && (cipher = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ciphersize * sizeof(BYTE))) == NULL) {
		success = false;
	}

	if (success && memcpy_s(cipher, ciphersize, plaintext.c_str(), plaintext.length()) != 0) {
		success = false;
	}

	ciphertempsize = ciphersize;
	ciphersize = (DWORD)plaintext.length();

	if (success && CryptEncrypt(key, 0, TRUE, 0, cipher, &ciphersize, ciphertempsize) == FALSE) {
		success = false;
	}

	ivandciphersize = ciphersize + blocksize;

	if (success && (ivandcipher = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ivandciphersize * sizeof(BYTE))) == NULL) {
		success = false;
	}

	if (success && (memcpy_s(ivandcipher, ivandciphersize, iv, blocksize) != 0 || memcpy_s(ivandcipher + blocksize, ivandciphersize, cipher, ciphersize) != 0)) {
		success = false;
	}

	if (success && (ciphertext = libencode::base64_encode(ivandcipher, ivandciphersize)) == "") {
		success = false;
	}

	if (ivandcipher) {
		HeapFree(GetProcessHeap(), 0, ivandcipher);
		ivandcipher = NULL;
	}

	if (cipher) {
		HeapFree(GetProcessHeap(), 0, cipher);
		cipher = NULL;
	}

	if (iv) {
		HeapFree(GetProcessHeap(), 0, iv);
		iv = NULL;
	}

	if (key) {
		CryptDestroyKey(key);
		key = NULL;
	}

	if (hCryptProv) {
		CryptReleaseContext(hCryptProv, 0);
		hCryptProv = NULL;
	}

	return ciphertext;
}

std::string libcrypt::decrypt(std::string password, std::string ciphertext) {
	std::string plaintext;
	bool success = true;
	HCRYPTKEY key = 0;
	HCRYPTPROV hCryptProv = 0;
	DWORD mode = CRYPT_MODE_CBC;
	DWORD padding = PKCS5_PADDING;
	DWORD blocksize = 0, blocksizelen = sizeof(DWORD);
	BYTE *iv = 0;
	BYTE *decoded = 0;
	BYTE *ivandcipher = 0;
	DWORD ivandciphersize = 0;

	if (success && derive_key_from_password(password, &key, &hCryptProv) == false) {
		success = false;
	}

	if (success && CryptSetKeyParam(key, KP_MODE, (BYTE*)&mode, 0) == FALSE) {
		success = false;
	}

	if (success && CryptSetKeyParam(key, KP_PADDING, (BYTE*)&padding, 0) == FALSE) {
		success = false;
	}

	if (success && CryptGetKeyParam(key, KP_BLOCKLEN, (BYTE*)&blocksize, &blocksizelen, 0) == FALSE) {
		success = false;
	}

	blocksize /= 8;

	if (success && (iv = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, blocksize * sizeof(BYTE))) == NULL) {
		success = false;
	}

	if (success && (ivandciphersize = libencode::base64_decode(&decoded, ciphertext.c_str())) == 0) {
		success = false;
	}

	ivandciphersize -= blocksize;

	if (success && (ivandcipher = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ivandciphersize * sizeof(BYTE))) == NULL) {
		success = false;
	}

	if (success && (memcpy_s(iv, blocksize, decoded, blocksize) != 0 || memcpy_s(ivandcipher, ivandciphersize, decoded + blocksize, ivandciphersize) != 0)) {
		success = false;
	}

	if (success && CryptSetKeyParam(key, KP_IV, iv, 0) == FALSE) {
		success = false;
	}

	if (CryptDecrypt(key, 0, TRUE, 0, ivandcipher, &ivandciphersize) == FALSE) {
		success = false;
	}

	ivandcipher[ivandciphersize] = 0;
	plaintext = std::string((char*)ivandcipher);

	if (iv) {
		HeapFree(GetProcessHeap(), 0, iv);
		iv = NULL;
	}

	if (decoded) {
		HeapFree(GetProcessHeap(), 0, decoded);
		decoded = NULL;
	}

	if (ivandcipher) {
		HeapFree(GetProcessHeap(), 0, ivandcipher);
		ivandcipher = NULL;
	}

	if (key) {
		CryptDestroyKey(key);
		key = NULL;
	}

	if (hCryptProv) {
		CryptReleaseContext(hCryptProv, 0);
		hCryptProv = NULL;
	}

	return plaintext;
}
