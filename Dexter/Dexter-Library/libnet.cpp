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

#include "libnet.h"

#include <winsock2.h>
#include <ws2tcpip.h>

DWORD libnet::LastError;

static bool _INITIALIZED_ = false;

bool libnet::init(void) {

	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return false;
	}

	_INITIALIZED_ = true;

	return _INITIALIZED_;
}

void libnet::finalize(void) {

	WSACleanup();
	_INITIALIZED_ = false;
}

bool libnet::is_ipv4_or_ipv6_address(std::wstring host) {

	if (!_INITIALIZED_) {
		return false;
	}

	struct sockaddr_in client;

	ZeroMemory(&client, sizeof(client));

	client.sin_family = AF_INET;

	if (InetPtonW(AF_INET, host.c_str(), &client.sin_addr.s_addr) != 1) {
		return false;
	}

	return true;
}

bool libnet::check_tcp_port_connectivity_byname(std::wstring hostname, unsigned short port) {

	if (!_INITIALIZED_) {
		return false;
	}

	ADDRINFOW hints;
	ADDRINFOW *result = NULL;
	SOCKET socket;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	std::wstring portW = std::to_wstring(port);

	if (GetAddrInfoW(hostname.c_str(), portW.c_str(), &hints, &result) != 0) {
		LastError = GetLastError();
		return false;
	}

	if ((socket = WSASocket(result->ai_family, result->ai_socktype, result->ai_protocol, NULL, 0, 0)) == INVALID_SOCKET) {
		LastError = GetLastError();
		FreeAddrInfoW(result);
		return false;
	}

	if (connect(socket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
		LastError = GetLastError();
		FreeAddrInfoW(result);
		return false;
	}

	if (closesocket(socket) == SOCKET_ERROR) {
		LastError = GetLastError();
		FreeAddrInfoW(result);
		return false;
	}

	FreeAddrInfoW(result);

	return true;
}

bool libnet::check_tcp_port_connectivity(std::wstring ip_address, unsigned short port) {

	if (!_INITIALIZED_) {
		return false;
	}

	SOCKET socket;
	struct sockaddr_in client;

	if ((socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)) == INVALID_SOCKET) {
		LastError = GetLastError();
		return false;
	}

	ZeroMemory(&client, sizeof(client));

	client.sin_family = AF_INET;
	client.sin_port = htons(port);

	if (InetPtonW(AF_INET, ip_address.c_str(), &client.sin_addr.s_addr) != 1) {
		LastError = GetLastError();
		return false;
	}

	if (connect(socket, (struct sockaddr*)&client, sizeof(client)) == SOCKET_ERROR) {
		LastError = GetLastError();
		return false;
	}

	if (closesocket(socket) == SOCKET_ERROR) {
		LastError = GetLastError();
		return false;
	}

	return true;
}
