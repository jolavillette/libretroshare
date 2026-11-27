/*******************************************************************************
 * libretroshare/src/util: rssocketcensus.cc                                   *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright (C) 2026  jolavillette                                            *
 *                                                                             *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU Lesser General Public License as              *
 * published by the Free Software Foundation, either version 3 of the          *
 * License, or (at your option) any later version.                             *
 *                                                                             *
 * This program is distributed in the hope that it will be useful,             *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the                *
 * GNU Lesser General Public License for more details.                         *
 *                                                                             *
 * You should have received a copy of the GNU Lesser General Public License    *
 * along with this program. If not, see <https://www.gnu.org/licenses/>.       *
 *                                                                             *
 *******************************************************************************/

// Debug probe: logs every socket this process holds, with the TCP segment and
// byte counters the kernel keeps for it. On Android nothing outside the
// process may read them, so this is the only way to tell which connection
// carries the packets the system counts for the application.

#include "util/rsdebug.h"

#ifdef __linux__

#include <arpa/inet.h>
#include <dirent.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>

static std::string addressToString(const sockaddr_storage& addr)
{
	char text[INET6_ADDRSTRLEN] = "";
	std::ostringstream out;
	if(addr.ss_family == AF_INET)
	{
		const sockaddr_in& in(reinterpret_cast<const sockaddr_in&>(addr));
		inet_ntop(AF_INET, &in.sin_addr, text, sizeof(text));
		out << text << ":" << ntohs(in.sin_port);
	}
	else if(addr.ss_family == AF_INET6)
	{
		const sockaddr_in6& in6(reinterpret_cast<const sockaddr_in6&>(addr));
		inet_ntop(AF_INET6, &in6.sin6_addr, text, sizeof(text));
		out << "[" << text << "]:" << ntohs(in6.sin6_port);
	}
	else if(addr.ss_family == AF_UNIX)
		out << "unix";
	else
		out << "family " << addr.ss_family;
	return out.str();
}

void rsLogSocketCensus()
{
	DIR* dir = opendir("/proc/self/fd");
	if(!dir) return;

	while(dirent* entry = readdir(dir))
	{
		char* end = nullptr;
		int fd = static_cast<int>(strtol(entry->d_name, &end, 10));
		if(end == entry->d_name || *end) continue;

		int type = 0;
		socklen_t length = sizeof(type);
		if(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length)) continue;

		sockaddr_storage local, peer;
		memset(&local, 0, sizeof(local));
		memset(&peer, 0, sizeof(peer));
		length = sizeof(local);
		getsockname(fd, reinterpret_cast<sockaddr*>(&local), &length);
		length = sizeof(peer);
		bool connected =
		        !getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &length);

		std::ostringstream line;
		line << "Socket census: fd " << fd << " "
		     << ( type == SOCK_STREAM ? "stream" :
		          type == SOCK_DGRAM ? "datagram" : "other" )
		     << " local " << addressToString(local);
		if(connected) line << " peer " << addressToString(peer);

		bool inet = local.ss_family == AF_INET || local.ss_family == AF_INET6;
		if(inet && type == SOCK_STREAM && connected)
		{
			tcp_info info;
			memset(&info, 0, sizeof(info));
			length = sizeof(info);
			if(!getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length))
				line << " segments out " << info.tcpi_segs_out
				     << " in " << info.tcpi_segs_in
				     << ", with data out " << info.tcpi_data_segs_out
				     << " in " << info.tcpi_data_segs_in
				     << ", bytes out " << info.tcpi_bytes_acked
				     << " in " << info.tcpi_bytes_received
				     << ", retransmitted " << info.tcpi_total_retrans;
		}
		RsInfo() << line.str();
	}
	closedir(dir);
}

#else // def __linux__

void rsLogSocketCensus() {}

#endif // def __linux__
