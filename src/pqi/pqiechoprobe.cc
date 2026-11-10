/*******************************************************************************
 * libretroshare/src/pqi: pqiechoprobe.cc                                      *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright 2026 by Retroshare Team <contact@retroshare.cc>                   *
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

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "pqi/pqiechoprobe.h"

static const uint32_t FLUSH_LAPSE_MS            = 60000 ;
static const uint32_t MAX_SAMPLES_PER_KEY       = 3 ;     // per friend, kind and service, per minute
static const uint32_t MAX_SAMPLES_PER_LAPSE     = 300 ;
static const uint32_t MIN_ITEM_SIZE             = 17 ;    // header is 8 bytes; tiny items match by nature
static const size_t   MAX_FINGERPRINTS          = 2000000 ;

static uint64_t nowMs()
{
	return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
	            std::chrono::system_clock::now().time_since_epoch()).count() ;
}

static std::string timeStr(uint64_t ms)
{
	uint64_t s = ms/1000 ;
	std::ostringstream o ;
	o << std::setfill('0') << std::setw(2) << (s/3600)%24 << ':' << std::setw(2) << (s/60)%60 << ':'
	  << std::setw(2) << s%60 << '.' << std::setw(3) << (uint32_t)(ms%1000) ;
	return o.str() ;
}

static const char *kindName(int k)
{
	return (k == 0)?"ECHO":((k == 1)?"DUP":"REPEAT") ;
}

PqiEchoProbe& PqiEchoProbe::instance()
{
	static PqiEchoProbe p ;
	return p ;
}

PqiEchoProbe::PqiEchoProbe()
    : mMtx("PqiEchoProbe"),mLastFlushMs(0),mSamplesThisLapse(0)
{
	const char *e = getenv("RS_ECHO_PROBE") ;
	mEnabled = (e != NULL && e[0] != '\0' && e[0] != '0') ;

	const char *f = getenv("RS_ECHO_PROBE_FILE") ;
	mFileName = (f != NULL && f[0] != '\0')?std::string(f):std::string("echo-probe.log") ;

	const char *w = getenv("RS_ECHO_PROBE_WINDOW") ;
	long secs = (w != NULL)?strtol(w,NULL,10):0 ;
	mWindowMs = uint64_t((secs > 0)?secs:60)*1000 ;

	mPeers.push_back(RsPeerId()) ;	// index 0 unused

	if(mEnabled)
		std::cerr << "(II) PqiEchoProbe: ON, writing to \"" << mFileName << "\", window " << mWindowMs/1000 << " s" << std::endl ;
}

// 64 bits multiplicative hash over 8 bytes words, then the tail. Not
// cryptographic: it only has to tell identical serialised items apart from
// different ones, and to be cheap enough to run on all the traffic.

uint64_t PqiEchoProbe::hash(const uint8_t *d,uint32_t size)
{
	uint64_t h = 0x9e3779b97f4a7c15ULL ^ size ;
	uint32_t i = 0 ;

	for(;i+8<=size;i+=8)
	{
		uint64_t w ;
		memcpy(&w,d+i,8) ;
		h ^= w ;
		h *= 0x100000001b3ULL ;
		h ^= h >> 29 ;
	}
	for(;i<size;++i)
	{
		h ^= d[i] ;
		h *= 0x100000001b3ULL ;
	}
	h ^= h >> 32 ;
	return h ;
}

bool PqiEchoProbe::ignoredService(uint16_t s)
{
	switch(s)
	{
		case 0x0016: // heartbeat
		case 0x0102: // status
		case 0x0021: // bandwidth control
		case 0x0020: // service info
		case 0x1011: // RTT
		case 0xAABB: // packet slicing probe
			return true ;
		default:
			return false ;
	}
}

std::string PqiEchoProbe::serviceName(uint16_t s)
{
	const char *n = NULL ;

	switch(s)
	{
		case 0x0011: n = "disc" ; break ;
		case 0x0012: n = "chat" ; break ;
		case 0x0013: n = "msg" ; break ;
		case 0x0014: n = "turtle" ; break ;
		case 0x0017: n = "filetransfer" ; break ;
		case 0x0018: n = "grouter" ; break ;
		case 0x0019: n = "filedb" ; break ;
		case 0x0027: n = "distantchat" ; break ;
		case 0x0028: n = "gxstunnel" ; break ;
		case 0x0101: n = "banlist" ; break ;
		case 0x0200: n = "nxs" ; break ;
		case 0x0211: n = "gxsid" ; break ;
		case 0x0215: n = "forums" ; break ;
		case 0x0216: n = "posted" ; break ;
		case 0x0217: n = "channels" ; break ;
		case 0x0218: n = "gxscircle" ; break ;
		case 0x0219: n = "reputation" ; break ;
		case 0x0230: n = "gxstrans" ; break ;
		case 0x2233: n = "gxsdistant" ; break ;
		default: break ;
	}

	std::ostringstream o ;
	if(n) o << n ;
	o << "(0x" << std::hex << std::setw(4) << std::setfill('0') << s << ")" ;
	return o.str() ;
}

uint16_t PqiEchoProbe::peerIdx(const RsPeerId& p)
{
	std::map<RsPeerId,uint16_t>::const_iterator it(mPeerIdx.find(p)) ;

	if(it != mPeerIdx.end())
		return it->second ;

	if(mPeers.size() >= 0xffff)
		return 0 ;

	uint16_t idx = uint16_t(mPeers.size()) ;
	mPeers.push_back(p) ;
	mPeerIdx[p] = idx ;
	return idx ;
}

void PqiEchoProbe::expire(uint64_t now)
{
	uint64_t limit = (now > mWindowMs)?(now - mWindowMs):0 ;

	while(!mOrder.empty() && (mOrder.front().first < limit || mSeen.size() > MAX_FINGERPRINTS))
	{
		mSeen.erase(mOrder.front().second) ;
		mOrder.pop_front() ;
	}
}

void PqiEchoProbe::sent(const RsPeerId& to,const void *data,uint32_t size)
{
	if(mEnabled)
		record(true,to,data,size) ;
}

void PqiEchoProbe::received(const RsPeerId& from,const void *data,uint32_t size)
{
	if(mEnabled)
		record(false,from,data,size) ;
}

void PqiEchoProbe::record(bool outgoing,const RsPeerId& peer,const void *data,uint32_t size)
{
	if(data == NULL || size < MIN_ITEM_SIZE)
		return ;

	const uint8_t *d = (const uint8_t*)data ;
	uint16_t service = uint16_t((d[1] << 8) | d[2]) ;
	uint8_t  subtype = d[3] ;

	if(ignoredService(service))
		return ;

	uint64_t fp = hash(d,size) ;	// off mutex
	uint64_t now = nowMs() ;

	std::string to_write ;

	{
		RS_STACK_MUTEX(mMtx) ;

		expire(now) ;

		uint16_t idx = peerIdx(peer) ;
		PeerStat& st(mStats[idx]) ;

		std::unordered_map<uint64_t,Seen>::iterator it(mSeen.find(fp)) ;
		bool fresh = (it == mSeen.end()) ;

		if(fresh)
		{
			it = mSeen.insert(std::make_pair(fp,Seen())).first ;
			mOrder.push_back(std::make_pair(now,fp)) ;
		}
		Seen& s(it->second) ;

		if(outgoing)
		{
			++st.out ;

			if(s.sent_ms == 0)
			{
				s.sent_ms = now ;
				s.sent_to = idx ;
			}
		}
		else
		{
			++st.in ;

			int kind = -1 ;
			uint64_t ref_ms = 0 ;
			uint16_t ref_peer = 0 ;

			if(!fresh && s.sent_ms != 0)
			{
				kind = ECHO ; ref_ms = s.sent_ms ; ref_peer = s.sent_to ;
			}
			else if(!fresh && s.recv_ms != 0)
			{
				kind = (s.recv_from == idx)?REPEAT:DUP ; ref_ms = s.recv_ms ; ref_peer = s.recv_from ;
			}

			if(s.recv_ms == 0)
			{
				s.recv_ms = now ;
				s.recv_from = idx ;
			}

			if(kind >= 0)
			{
				++st.count[kind][service] ;

				uint32_t key = (uint32_t(kind) << 16) | service ;

				if(st.samples[key] < MAX_SAMPLES_PER_KEY && mSamplesThisLapse < MAX_SAMPLES_PER_LAPSE)
				{
					++st.samples[key] ;
					++mSamplesThisLapse ;

					std::ostringstream o ;
					o << kindName(kind) << " " << timeStr(now) << " from=" << peer
					  << " svc=" << serviceName(service) << "/0x" << std::hex << std::setw(2) << std::setfill('0') << int(subtype) << std::dec
					  << " size=" << size << " fp=" << std::hex << std::setw(16) << std::setfill('0') << fp << std::dec
					  << " : we " << ((kind == ECHO)?"SENT it to ":"RECEIVED it from ") << mPeers[ref_peer]
					  << " " << (now - ref_ms) << " ms earlier" << std::endl ;
					mPending.push_back(o.str()) ;
				}
			}
		}

		if(mLastFlushMs == 0)
			mLastFlushMs = now ;

		if(now >= mLastFlushMs + FLUSH_LAPSE_MS)
		{
			for(uint32_t i=0;i<mPending.size();++i)
				to_write += mPending[i] ;
			mPending.clear() ;

			to_write += summary(now) ;

			mStats.clear() ;
			mSamplesThisLapse = 0 ;
			mLastFlushMs = now ;
		}
	}

	// Off the probe mutex. The caller may still hold its streamer mutex: this is a
	// small append once a minute, and it does not call into any other service.

	if(!to_write.empty())
	{
		std::ofstream f(mFileName.c_str(),std::ios::app) ;
		if(f)
			f << to_write ;
	}
}

std::string PqiEchoProbe::summary(uint64_t now)
{
	std::ostringstream o ;

	o << "SUMMARY " << timeStr(now) << " last " << (now - mLastFlushMs)/1000 << " s, "
	  << mSeen.size() << " fingerprints in a " << mWindowMs/1000 << " s window" << std::endl ;

	uint32_t shown = 0 ;

	for(std::map<uint16_t,PeerStat>::const_iterator it(mStats.begin());it!=mStats.end();++it)
	{
		const PeerStat& st(it->second) ;

		if(st.count[0].empty() && st.count[1].empty() && st.count[2].empty())
			continue ;

		++shown ;
		o << "  peer " << mPeers[it->first] << " in=" << st.in << " out=" << st.out ;

		for(int k=0;k<3;++k)
			if(!st.count[k].empty())
			{
				o << " " << kindName(k) << ":" ;
				for(std::map<uint16_t,uint32_t>::const_iterator c(st.count[k].begin());c!=st.count[k].end();++c)
					o << " " << serviceName(c->first) << "=" << c->second ;
			}
		o << std::endl ;
	}

	if(shown == 0)
		o << "  no echo, duplicate or repeat from any friend" << std::endl ;

	return o.str() ;
}
