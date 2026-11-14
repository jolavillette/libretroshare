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

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>

// TCP state of friend links (debug/tr-race-probe). Socket headers first: on
// Windows winsock2 must come before anything that pulls windows.h.
#include "util/rsnet.h"
#ifdef WINDOWS_SYS
#	include <mstcpip.h>
#else
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/ioctl.h>
#	include <netinet/in.h>
#	include <netinet/tcp.h>
#endif

#include "pqi/pqiechoprobe.h"

static const uint32_t FLUSH_LAPSE_MS            = 60000 ;
static const uint32_t MAX_SAMPLES_PER_KEY       = 3 ;     // per friend, kind and service, per minute
static const uint32_t MAX_SAMPLES_PER_LAPSE     = 300 ;
static const uint32_t MIN_ITEM_SIZE             = 17 ;    // header is 8 bytes; tiny items match by nature
static const size_t   MAX_FINGERPRINTS          = 2000000 ;
static const uint64_t BURST_HALF_WIDTH_MS       = 1000 ;  // burst = items sent to the same friend within 1 s of the echoed one
static const uint64_t WATCH_DURATION_MS         = 120000 ;
static const uint32_t MAX_OPEN_WATCHES          = 30 ;
static const uint32_t MAX_WATCHES_PER_LAPSE     = 10 ;    // tunnel ok and data items
static const uint32_t MAX_MINOR_WATCHES_PER_LAPSE = 3 ;   // file transfer, file map, chunk crc items
static const uint32_t MAX_ITEMS_PER_WATCH       = 400 ;
static const uint32_t MAX_UNRETURNED_LINES      = 40 ;
static const uint32_t MAX_MULTISEND_LINES       = 200 ;   // per minute, in the probe file
static const uint32_t MAX_MULTISEND_STDERR      = 10 ;    // per minute, on stderr

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
    : mMtx("PqiEchoProbe"),mLastFlushMs(0),mSamplesThisLapse(0),
      mNextWatchId(1),mWatchesThisLapse(0),mMinorWatchesThisLapse(0),
      mMultiSendThisLapse(0),mMultiSendLinesThisLapse(0),mQWaitLinesThisLapse(0),mQStale(0),mQMatched(0),mTrHeldLinesThisLapse(0)
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

// Turtle items routed by tunnel id: tunnel ok, generic data, generic fast data,
// and the file transfer items (request, data, map, map request, chunk crc). All
// of them start with the 32 bits tunnel id right after the 8 bytes header.

bool PqiEchoProbe::isTunnelItem(uint16_t service,uint8_t subtype)
{
	if(service != 0x0014)
		return false ;

	switch(subtype)
	{
		case 0x04: case 0x07: case 0x08: case 0x0a: case 0x10: case 0x11: case 0x14: case 0x15: case 0x16:
			return true ;
		default:
			return false ;
	}
}

std::string PqiEchoProbe::subtypeName(uint16_t service,uint8_t subtype)
{
	std::ostringstream o ;
	o << serviceName(service) << "/0x" << std::hex << std::setw(2) << std::setfill('0') << int(subtype) << std::dec ;

	if(service == 0x0014)
	{
		const char *n = NULL ;
		switch(subtype)
		{
			case 0x01: n = "search" ; break ;
			case 0x02: n = "search_result" ; break ;
			case 0x03: n = "open_tunnel" ; break ;
			case 0x04: n = "tunnel_ok" ; break ;
			case 0x07: n = "file_request" ; break ;
			case 0x08: n = "file_data" ; break ;
			case 0x09: n = "regexp_search" ; break ;
			case 0x0a: n = "generic_data" ; break ;
			case 0x0b: n = "generic_search" ; break ;
			case 0x0c: n = "generic_search_result" ; break ;
			case 0x10: n = "file_map" ; break ;
			case 0x11: n = "file_map_request" ; break ;
			case 0x14: n = "chunk_crc" ; break ;
			case 0x15: n = "chunk_crc_request" ; break ;
			case 0x16: n = "generic_fast_data" ; break ;
			default: break ;
		}
		if(n) o << "(" << n << ")" ;
	}
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
	{
		RS_STACK_MUTEX(mMtx) ;
		if(outgoing)	// the buffer may reuse the address of an item tracked for queue delay
			mQueued.erase(data) ;
		else			// heartbeats & co still prove the link is alive
			noteReceived(peerIdx(peer),nowMs(),service,subtype) ;
		return ;
	}

	uint64_t fp = hash(d,size) ;	// off mutex
	uint64_t now = nowMs() ;

	uint32_t tunnel_id = 0 ;
	if(isTunnelItem(service,subtype) && size >= 12)
		tunnel_id = (uint32_t(d[8]) << 24) | (uint32_t(d[9]) << 16) | (uint32_t(d[10]) << 8) | uint32_t(d[11]) ;

	// Generic (fast) data: header, tunnel id, 32 bits length, payload. An encrypted file
	// transfer payload starts with 0xae 0xad, a format byte, a 12 bytes IV and the clear
	// size of the inner ft item, little endian (ftServer::encryptItem).
	uint32_t ft_inner = 0 ;
	if(service == 0x0014 && (subtype == 0x0a || subtype == 0x16) && size >= 36 && d[16] == 0xae && d[17] == 0xad)
		ft_inner = uint32_t(d[32]) | (uint32_t(d[33]) << 8) | (uint32_t(d[34]) << 16) | (uint32_t(d[35]) << 24) ;

	std::string to_write ;
	std::string to_stderr ;

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

			{
				Queued q ;
				q.ms = now ; q.fp = fp ; q.size = size ; q.peer = idx ; q.service = service ; q.subtype = subtype ;
				mQueued[data] = q ;
			}

			SentRec r ;
			r.ms = now ; r.fp = fp ; r.seq = ++mSendSeq[idx] ; r.size = size ;
			r.tunnel_id = tunnel_id ; r.ft_inner = ft_inner ; r.service = service ; r.subtype = subtype ;

			std::deque<SentRec>& log(mSentLog[idx]) ;
			log.push_back(r) ;
			while(!log.empty() && log.front().ms + mWindowMs + BURST_HALF_WIDTH_MS < now)
				log.pop_front() ;

			// a burst opened less than a second after its trigger item was sent is still collecting

			for(std::map<uint32_t,Watch>::iterator w(mWatches.begin());w!=mWatches.end();++w)
				if(w->second.to == idx && now <= w->second.t0 + BURST_HALF_WIDTH_MS && w->second.items.size() < MAX_ITEMS_PER_WATCH)
				{
					WatchItem wi ;
					wi.s = r ;
					w->second.items.push_back(wi) ;
					mWatchFp.insert(std::make_pair(fp,std::make_pair(w->first,uint32_t(w->second.items.size()-1)))) ;
				}

			if(s.sent_ms != 0 && idx != s.sent_to && idx != s.sent_to2)
			{
				if(s.sent_to2 == 0)
					s.sent_to2 = idx ;
				if(s.n_sent_peers < 255)
					++s.n_sent_peers ;

				if(isTunnelItem(service,subtype))
				{
					++mMultiSendThisLapse ;

					std::ostringstream o ;
					o << "MULTISEND " << timeStr(now) << " to=" << peer << " " << subtypeName(service,subtype)
					  << " size=" << size << " tunnel=0x" << std::hex << std::setw(8) << std::setfill('0') << tunnel_id
					  << " fp=" << std::setw(16) << fp << std::dec
					  << " : the same item was serialised for " << mPeers[s.sent_to] << " " << (now - s.sent_ms)
					  << " ms earlier (" << int(s.n_sent_peers) << " friends now)" << std::endl ;

					if(mMultiSendLinesThisLapse < MAX_MULTISEND_LINES)
						mPending.push_back(o.str()) ;
					if(mMultiSendLinesThisLapse < MAX_MULTISEND_STDERR)
						to_stderr += "(WW) PqiEchoProbe: " + o.str() ;
					++mMultiSendLinesThisLapse ;
				}
			}

			if(s.sent_ms == 0)
			{
				s.sent_ms = now ;
				s.sent_to = idx ;
				s.n_sent_peers = 1 ;
			}
		}
		else
		{
			++st.in ;

			noteReceived(idx,now,service,subtype) ;

			// tunnel request: 8 bytes header, 20 bytes hash, 32 bits request id (big endian), ...
			if(service == 0x0014 && subtype == 0x03 && size == 38)
			{
				uint32_t rid = (uint32_t(d[28]) << 24) | (uint32_t(d[29]) << 16) | (uint32_t(d[30]) << 8) | uint32_t(d[31]) ;
				std::pair<uint32_t,uint16_t> key(rid,idx) ;
				if(mTrArrival.insert(std::make_pair(key,now)).second)
					mTrArrivalOrder.push_back(std::make_pair(now,key)) ;
				while(!mTrArrivalOrder.empty() && mTrArrivalOrder.front().first + 900000 < now)
				{
					mTrArrival.erase(mTrArrivalOrder.front().second) ;
					mTrArrivalOrder.pop_front() ;
				}
			}

			uint64_t rseq = ++mRecvSeq[idx] ;

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

			if(kind == ECHO && isTunnelItem(service,subtype))
			{
				openWatch(ref_peer,idx,ref_ms,now,fp,service,subtype) ;

				// remember whether we also serialised the trigger item for another friend (the echoing one?)
				for(std::map<uint32_t,Watch>::iterator w(mWatches.begin());w!=mWatches.end();++w)
					if(w->second.trigger_fp == fp && w->second.trigger_also_sent_to == 0)
						w->second.trigger_also_sent_to = s.sent_to2 ;
			}

			// is it an item of a burst we are watching?

			std::pair<std::unordered_multimap<uint64_t,std::pair<uint32_t,uint32_t> >::iterator,
			          std::unordered_multimap<uint64_t,std::pair<uint32_t,uint32_t> >::iterator> rg(mWatchFp.equal_range(fp)) ;

			for(std::unordered_multimap<uint64_t,std::pair<uint32_t,uint32_t> >::iterator f(rg.first);f!=rg.second;++f)
			{
				std::map<uint32_t,Watch>::iterator w(mWatches.find(f->second.first)) ;
				if(w == mWatches.end() || f->second.second >= w->second.items.size())
					continue ;

				WatchItem& wi(w->second.items[f->second.second]) ;
				if(wi.back_count < 0xffff)
					++wi.back_count ;
				if(wi.back_ms == 0)
				{
					wi.back_ms = now ;
					wi.back_from = idx ;
					wi.back_seq = rseq ;
				}
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
					  << " " << (now - ref_ms) << " ms earlier" ;
					if(kind == ECHO && s.sent_to2 != 0)
						o << " (also sent to " << mPeers[s.sent_to2] << ((s.sent_to2 == idx)?", the friend sending it back":"") << ")" ;
					o << std::endl ;
					mPending.push_back(o.str()) ;
				}
			}
		}

		closeWatches(now,false) ;

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
			mWatchesThisLapse = 0 ;
			mMinorWatchesThisLapse = 0 ;
			mMultiSendThisLapse = 0 ;
			mMultiSendLinesThisLapse = 0 ;
			mQWaitLinesThisLapse = 0 ;
			mQStale = 0 ;
			mQMatched = 0 ;
			mQDelay.clear() ;
			mTrSend.clear() ;
			mTrHeldLinesThisLapse = 0 ;

			// items dropped from a queue (connection reset) never leave it: forget them after 15 min
			for(std::unordered_map<const void*,Queued>::iterator q(mQueued.begin());q!=mQueued.end();)
				if(q->second.ms + 900000 < now) q = mQueued.erase(q) ; else ++q ;
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
	if(!to_stderr.empty())
		std::cerr << to_stderr << std::flush ;
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

	o << "  turtle tunnel items serialised for more than one friend: " << mMultiSendThisLapse << std::endl ;

	// Output queue delays (serialisation -> written), friends/classes with a wait above 5 s.
	{
		uint32_t shown_q = 0 ;
		for(std::map<std::pair<uint16_t,int>,QDelayStat>::const_iterator q(mQDelay.begin());q!=mQDelay.end();++q)
			if(q->second.max_ms > 5000)
			{
				++shown_q ;
				o << "  QDELAY " << mPeers[q->first.first] << " " << delayClassName(q->first.second)
				  << ": n=" << q->second.n << " avg=" << (q->second.n?q->second.sum_ms/q->second.n:0) << "ms max=" << q->second.max_ms
				  << "ms >5s=" << q->second.over5 << " >20s=" << q->second.over20 << std::endl ;
			}
		o << "  output queue: " << mQueued.size() << " items waiting or untracked, " << shown_q << " friend/class pairs with a wait above 5 s, "
		  << mQMatched << " items measured, " << mQStale << " stale pointers ignored" << std::endl ;
	}

	// Tunnel requests sent, per friend (debug/tr-race-probe). "nagle" = left our queue
	// while the socket still had bytes queued and TCP_NODELAY was off: the kernel may
	// have held it until the previous segment was acknowledged.
	for(std::map<uint16_t,TrSendStat>::const_iterator t(mTrSend.begin());t!=mTrSend.end();++t)
	{
		const TrSendStat& m(t->second) ;
		const TrSendStat& a(mTrSendTotal[t->first]) ;
		o << "TRSEND " << timeStr(now) << " to=" << mPeers[t->first] << " last minute: " << m.n << " sent (" << m.own << " ours)"
		  << ", queue wait avg " << (m.n?m.wait_sum/m.n:0) << " ms max " << m.wait_max << " ms"
		  << ", socket busy " << m.n_sendq << " (max " << m.sendq_max << " B), nagle " << m.n_nagle
		  << ", nodelay off " << m.n_nodelay_off << ", unknown " << m.n_unknown
		  << "; since start: " << a.n << " sent, socket busy " << a.n_sendq << ", nagle " << a.n_nagle << std::endl ;
	}

	// Kernel view of every friend link, once a minute.
	for(std::map<uint16_t,int>::const_iterator sk(mSockets.begin());sk!=mSockets.end();++sk)
		o << "LINK " << timeStr(now) << " " << mPeers[sk->first] << " " << snapStr(tcpSnap(sk->second)) << std::endl ;

	return o.str() ;
}

//=============================================================================//
//                              Burst follow-up                                //
//=============================================================================//

void PqiEchoProbe::openWatch(uint16_t to,uint16_t from,uint64_t t0,uint64_t now,uint64_t fp,uint16_t service,uint8_t subtype)
{
	// one burst per friend and second: the other echoes of the same burst are part of it

	for(std::map<uint32_t,Watch>::const_iterator w(mWatches.begin());w!=mWatches.end();++w)
		if(w->second.to == to && t0 + BURST_HALF_WIDTH_MS >= w->second.t0 && t0 <= w->second.t0 + BURST_HALF_WIDTH_MS)
			return ;

	if(mWatches.size() >= MAX_OPEN_WATCHES)
		return ;

	bool major = (subtype == 0x04 || subtype == 0x0a || subtype == 0x16) ;

	if(major)
	{
		if(mWatchesThisLapse >= MAX_WATCHES_PER_LAPSE) return ;
		++mWatchesThisLapse ;
	}
	else
	{
		if(mMinorWatchesThisLapse >= MAX_MINOR_WATCHES_PER_LAPSE) return ;
		++mMinorWatchesThisLapse ;
	}

	uint32_t id = mNextWatchId++ ;
	Watch& w(mWatches[id]) ;

	w.id = id ; w.to = to ; w.trigger_from = from ; w.t0 = t0 ; w.trigger_ms = now ;
	w.trigger_fp = fp ; w.trigger_service = service ; w.trigger_subtype = subtype ;
	w.trigger_also_sent_to = 0 ;

	const std::deque<SentRec>& log(mSentLog[to]) ;

	for(std::deque<SentRec>::const_iterator it(log.begin());it!=log.end() && w.items.size() < MAX_ITEMS_PER_WATCH;++it)
		if(it->ms + BURST_HALF_WIDTH_MS >= t0 && it->ms <= t0 + BURST_HALF_WIDTH_MS)
		{
			WatchItem wi ;
			wi.s = *it ;
			w.items.push_back(wi) ;
			mWatchFp.insert(std::make_pair(it->fp,std::make_pair(id,uint32_t(w.items.size()-1)))) ;
		}
}

void PqiEchoProbe::closeWatches(uint64_t now,bool all)
{
	for(std::map<uint32_t,Watch>::iterator w(mWatches.begin());w!=mWatches.end();)
	{
		if(!all && now < w->second.trigger_ms + WATCH_DURATION_MS)
		{
			++w ;
			continue ;
		}

		mPending.push_back(watchReport(w->second)) ;

		for(uint32_t i=0;i<w->second.items.size();++i)
		{
			std::pair<std::unordered_multimap<uint64_t,std::pair<uint32_t,uint32_t> >::iterator,
			          std::unordered_multimap<uint64_t,std::pair<uint32_t,uint32_t> >::iterator> rg(mWatchFp.equal_range(w->second.items[i].s.fp)) ;

			for(std::unordered_multimap<uint64_t,std::pair<uint32_t,uint32_t> >::iterator f(rg.first);f!=rg.second;)
				if(f->second.first == w->first)
					f = mWatchFp.erase(f) ;
				else
					++f ;
		}
		mWatches.erase(w++) ;
	}
}

std::string PqiEchoProbe::watchReport(const Watch& w)
{
	std::ostringstream o ;

	uint32_t n = 0, back = 0 ;
	uint32_t n_tun = 0, back_tun = 0, n_turtle = 0, back_turtle = 0, n_other = 0, back_other = 0 ;
	std::map<uint16_t,uint32_t> via ;
	std::map<uint16_t,std::vector<uint64_t> > rseqs ;          // per returning friend, ranks in its stream
	std::vector<uint64_t> back_send_seqs ;
	std::vector<std::pair<uint64_t,uint64_t> > send_back ;     // (send seq, back ms) of returned items
	uint64_t first_back = 0, last_back = 0, first_sent = 0, last_sent = 0 ;
	std::set<uint32_t> tunnels, back_tunnels ;

	for(uint32_t i=0;i<w.items.size();++i)
	{
		const WatchItem& wi(w.items[i]) ;
		bool tun = isTunnelItem(wi.s.service,wi.s.subtype) ;
		bool returned = (wi.back_ms != 0) ;

		++n ;
		if(tun) { ++n_tun ; tunnels.insert(wi.s.tunnel_id) ; }
		else if(wi.s.service == 0x0014) ++n_turtle ;
		else ++n_other ;

		if(returned)
		{
			++back ;
			if(tun) { ++back_tun ; back_tunnels.insert(wi.s.tunnel_id) ; }
			else if(wi.s.service == 0x0014) ++back_turtle ;
			else ++back_other ;

			++via[wi.back_from] ;
			rseqs[wi.back_from].push_back(wi.back_seq) ;
			back_send_seqs.push_back(wi.s.seq) ;
			send_back.push_back(std::make_pair(wi.s.seq,wi.back_ms)) ;

			if(first_back == 0 || wi.back_ms < first_back) first_back = wi.back_ms ;
			if(wi.back_ms > last_back) last_back = wi.back_ms ;
			if(first_sent == 0 || wi.s.ms < first_sent) first_sent = wi.s.ms ;
			if(wi.s.ms > last_sent) last_sent = wi.s.ms ;
		}
	}

	o << "BURST #" << w.id << " " << timeStr(w.trigger_ms) << " to=" << mPeers[w.to]
	  << " trigger " << subtypeName(w.trigger_service,w.trigger_subtype)
	  << " fp=" << std::hex << std::setw(16) << std::setfill('0') << w.trigger_fp << std::dec
	  << " sent to it at " << timeStr(w.t0) << ", echoed by " << mPeers[w.trigger_from]
	  << " " << (w.trigger_ms - w.t0) << " ms later" << std::endl ;

	o << "  did WE also send the trigger item to another friend? "
	  << ((w.trigger_also_sent_to == 0)?std::string("no"):("YES, to " + mPeers[w.trigger_also_sent_to].toStdString()
	      + ((w.trigger_also_sent_to == w.trigger_from)?" = the friend that echoed it":"")))
	  << std::endl ;

	o << "  burst = items sent to " << mPeers[w.to] << " within " << BURST_HALF_WIDTH_MS << " ms of the trigger: " << n
	  << ", returned within " << WATCH_DURATION_MS/1000 << " s: " << back
	  << " | turtle tunnel items " << back_tun << "/" << n_tun << " (tunnels " << back_tunnels.size() << "/" << tunnels.size() << ")"
	  << ", other turtle " << back_turtle << "/" << n_turtle
	  << ", other services " << back_other << "/" << n_other << std::endl ;

	if(back > 0)
	{
		o << "  returned via:" ;
		for(std::map<uint16_t,uint32_t>::const_iterator v(via.begin());v!=via.end();++v)
			o << " " << mPeers[v->first] << "=" << v->second ;
		o << std::endl ;

		// is what came back one contiguous piece of our stream to U, in the same order?

		std::sort(back_send_seqs.begin(),back_send_seqs.end()) ;
		uint32_t runs = 1 ;
		for(uint32_t i=1;i<back_send_seqs.size();++i)
			if(back_send_seqs[i] != back_send_seqs[i-1]+1)
				++runs ;

		std::sort(send_back.begin(),send_back.end()) ;
		bool same_order = true ;
		for(uint32_t i=1;i<send_back.size();++i)
			if(send_back[i].second < send_back[i-1].second)
				same_order = false ;

		o << "  in our stream to " << mPeers[w.to] << ": returned items form " << runs << " contiguous run(s), "
		  << (same_order?"same order":"order CHANGED")
		  << "; sent over " << (last_sent - first_sent) << " ms, came back over " << (last_back - first_back) << " ms"
		  << ", delay " << (first_back - first_sent) << ".." << (last_back - first_sent) << " ms" << std::endl ;

		for(std::map<uint16_t,std::vector<uint64_t> >::iterator r(rseqs.begin());r!=rseqs.end();++r)
		{
			std::vector<uint64_t>& v(r->second) ;
			std::sort(v.begin(),v.end()) ;
			uint64_t span = v.back() - v.front() + 1 ;
			o << "  in the stream from " << mPeers[r->first] << ": " << v.size() << " returned item(s) over " << span
			  << " consecutive incoming item(s) (" << (span - v.size()) << " other items interleaved)" << std::endl ;
		}
	}

	uint32_t unreturned_shown = 0, unreturned_hidden = 0 ;

	for(uint32_t i=0;i<w.items.size();++i)
	{
		const WatchItem& wi(w.items[i]) ;
		bool returned = (wi.back_ms != 0) ;

		if(!returned && !isTunnelItem(wi.s.service,wi.s.subtype))
		{
			if(unreturned_shown >= MAX_UNRETURNED_LINES) { ++unreturned_hidden ; continue ; }
			++unreturned_shown ;
		}

		o << "    " << ((wi.s.ms >= w.t0)?"+":"-") << ((wi.s.ms >= w.t0)?(wi.s.ms - w.t0):(w.t0 - wi.s.ms)) << "ms"
		  << " seq=" << wi.s.seq << " " << subtypeName(wi.s.service,wi.s.subtype) << " size=" << wi.s.size ;
		if(wi.s.tunnel_id != 0)
			o << " tunnel=0x" << std::hex << std::setw(8) << std::setfill('0') << wi.s.tunnel_id << std::dec ;
		if(wi.s.ft_inner != 0)
			o << " enc-ft inner=" << wi.s.ft_inner
			  << ((wi.s.ft_inner == 24)?"(file_request|1-word file_map)":(wi.s.ft_inner == 16)?"(map_req|crc_req)":
			      (wi.s.ft_inner == 36)?"(chunk_crc|4-word file_map)":(wi.s.ft_inner >= 1024)?"(file_data)":"") ;
		if(wi.s.fp == w.trigger_fp)
			o << " [trigger]" ;

		if(returned)
			o << " -> BACK from " << mPeers[wi.back_from] << " +" << (wi.back_ms - wi.s.ms) << " ms (in-seq " << wi.back_seq << ")"
			  << ((wi.back_count > 1)?" x":"") ;
		else
			o << " -> not back" ;
		if(returned && wi.back_count > 1)
			o << wi.back_count ;
		o << std::endl ;
	}
	if(unreturned_hidden > 0)
		o << "    ... " << unreturned_hidden << " more non tunnel items, not back" << std::endl ;

	return o.str() ;
}

//=============================================================================//
//                            Output queue delay                               //
//=============================================================================//

int PqiEchoProbe::delayClass(uint16_t service,uint8_t subtype)
{
	if(service != 0x0014)
		return 6 ;
	switch(subtype)
	{
		case 0x03: return 0 ;                         // tunnel request
		case 0x04: return 1 ;                         // tunnel result
		case 0x0a: case 0x16: return 2 ;              // generic (fast) data
		case 0x07: case 0x08: case 0x10: case 0x11: case 0x14: case 0x15: return 3 ;	// clear file transfer
		case 0x01: case 0x09: case 0x0b: return 4 ;   // searches
		default: return 5 ;
	}
}

const char *PqiEchoProbe::delayClassName(int c)
{
	static const char *n[] = { "turtle_tunnel_request","turtle_tunnel_ok","turtle_generic_data","turtle_file_transfer","turtle_search","turtle_other","other_services" } ;
	return (c >= 0 && c <= 6)?n[c]:"?" ;
}

void PqiEchoProbe::dequeued(const RsPeerId& /*to*/,const void *data)
{
	if(!mEnabled || data == NULL)
		return ;

	uint64_t now = nowMs() ;
	std::string line ;

	{
		RS_STACK_MUTEX(mMtx) ;

		std::unordered_map<const void*,Queued>::iterator q(mQueued.find(data)) ;
		if(q == mQueued.end())
			return ;

		// Same pointer, same item? (the address may have been reused by another buffer)
		if(hash((const uint8_t*)data,q->second.size) != q->second.fp)
		{
			++mQStale ;
			mQueued.erase(q) ;
			return ;
		}
		++mQMatched ;

		uint32_t wait = uint32_t((now > q->second.ms)?(now - q->second.ms):0) ;
		int c = delayClass(q->second.service,q->second.subtype) ;

		QDelayStat& st(mQDelay[std::make_pair(q->second.peer,c)]) ;
		++st.n ;
		st.sum_ms += wait ;
		if(wait > st.max_ms) st.max_ms = wait ;
		if(wait > 5000)  ++st.over5 ;
		if(wait > 20000) ++st.over20 ;

		// Tunnel request leaving our queue: socket state right now (debug/tr-race-probe).
		if(c == 0)
		{
			const uint8_t *d = (const uint8_t*)data ;
			uint32_t rid = 0 ;
			uint16_t depth = 0xffff ;
			if(q->second.size == 38)
			{
				rid   = (uint32_t(d[28]) << 24) | (uint32_t(d[29]) << 16) | (uint32_t(d[30]) << 8) | uint32_t(d[31]) ;
				depth = uint16_t((d[36] << 8) | d[37]) ;
			}
			bool own = (depth == 1) ;	// our own request (or a relay that did not increase the depth)

			TcpSnap s ;
			std::map<uint16_t,int>::const_iterator sk(mSockets.find(q->second.peer)) ;
			if(sk != mSockets.end())
				s = tcpSnap(sk->second) ;

			TrSendStat *stats[2] = { &mTrSend[q->second.peer], &mTrSendTotal[q->second.peer] } ;
			for(int i=0;i<2;++i)
			{
				TrSendStat& t(*stats[i]) ;
				++t.n ;
				if(own) ++t.own ;
				t.wait_sum += wait ;
				if(wait > t.wait_max) t.wait_max = wait ;
				if(!s.ok || s.nodelay < 0) ++t.n_unknown ;
				if(s.nodelay == 0) ++t.n_nodelay_off ;
				if(s.sendq > 0)
				{
					++t.n_sendq ;
					if(s.sendq > t.sendq_max) t.sendq_max = s.sendq ;
					if(s.nodelay == 0) ++t.n_nagle ;
				}
			}

			// Our own requests that may be held: one line each (capped), with the request
			// id, to match against the friend's journal (DIRECTLOST lines).
			if(own && ((s.sendq > 0 && s.nodelay != 1) || wait > 20) && mTrHeldLinesThisLapse < 200)
			{
				++mTrHeldLinesThisLapse ;
				std::ostringstream o ;
				o << "TRHELD " << timeStr(now) << " req=" << std::hex << std::setw(8) << std::setfill('0') << rid << std::dec << std::setfill(' ')
				  << " to=" << mPeers[q->second.peer] << " waited " << wait << " ms in our queue; socket: " << snapStr(s) << std::endl ;
				mPending.push_back(o.str()) ;
			}
		}

		// Tunnel requests and results that wait more than 20 s reach the friend after
		// its own 20 s result window: worth a line each.
		if(c <= 2 && wait > 20000 && mQWaitLinesThisLapse < 100)
		{
			++mQWaitLinesThisLapse ;
			std::ostringstream o ;
			o << "QWAIT " << timeStr(now) << " to=" << mPeers[q->second.peer] << " " << delayClassName(c)
			  << " size=" << q->second.size << " waited " << wait << " ms in our output queue" << std::endl ;
			mPending.push_back(o.str()) ;
		}
		mQueued.erase(q) ;
	}
}

//=============================================================================//
//                       Link stall / resume (receiving side)                  //
//=============================================================================//

static const uint64_t RESUME_GAP_MS    = 20000 ;   // silence that counts as a stall
static const uint64_t RESUME_WINDOW_MS = 3000 ;    // burst counted for this long after the silence

void PqiEchoProbe::noteReceived(uint16_t idx,uint64_t now,uint16_t service,uint8_t subtype)
{
	// close a finished burst count
	std::map<uint16_t,Resume>::iterator r(mResumes.find(idx)) ;
	if(r != mResumes.end() && now > r->second.start_ms + RESUME_WINDOW_MS)
	{
		std::ostringstream o ;
		o << "RESUME " << timeStr(r->second.start_ms) << " from=" << mPeers[idx] << " after " << r->second.gap_ms/1000
		  << " s of silence: " << r->second.n << " items in the next " << RESUME_WINDOW_MS/1000 << " s (tunnel requests "
		  << r->second.n_tr << ", tunnel ok " << r->second.n_ok << ", tunnel data " << r->second.n_data
		  << ", other turtle " << r->second.n_other_turtle << ")" << std::endl ;
		mPending.push_back(o.str()) ;
		mResumes.erase(r) ;
		r = mResumes.end() ;
	}

	std::map<uint16_t,uint64_t>::iterator l(mLastRx.find(idx)) ;

	if(l != mLastRx.end() && now > l->second + RESUME_GAP_MS && r == mResumes.end())
	{
		Resume& nr(mResumes[idx]) ;
		nr.start_ms = now ;
		nr.gap_ms   = now - l->second ;
		r = mResumes.find(idx) ;
	}

	if(r != mResumes.end())
	{
		++r->second.n ;
		if(service == 0x0014)
		{
			if(subtype == 0x03) ++r->second.n_tr ;
			else if(subtype == 0x04) ++r->second.n_ok ;
			else if(subtype == 0x0a || subtype == 0x16) ++r->second.n_data ;
			else ++r->second.n_other_turtle ;
		}
	}

	mLastRx[idx] = now ;
}

uint64_t PqiEchoProbe::trArrival(uint32_t rid,const RsPeerId& from)
{
	if(!mEnabled)
		return 0 ;

	RS_STACK_MUTEX(mMtx) ;

	std::map<RsPeerId,uint16_t>::const_iterator p(mPeerIdx.find(from)) ;
	if(p == mPeerIdx.end())
		return 0 ;

	std::map<std::pair<uint32_t,uint16_t>,uint64_t>::const_iterator it(mTrArrival.find(std::make_pair(rid,p->second))) ;
	return (it == mTrArrival.end())?0:it->second ;
}

//=============================================================================//
//                 TCP state of friend links (debug/tr-race-probe)             //
//=============================================================================//

void PqiEchoProbe::setSocket(const RsPeerId& peer,int fd)
{
	if(!mEnabled)
		return ;
	RS_STACK_MUTEX(mMtx) ;
	mSockets[peerIdx(peer)] = fd ;
}

void PqiEchoProbe::clearSocket(const RsPeerId& peer,int fd)
{
	if(!mEnabled)
		return ;
	RS_STACK_MUTEX(mMtx) ;
	std::map<uint16_t,int>::iterator it(mSockets.find(peerIdx(peer))) ;
	if(it != mSockets.end() && it->second == fd)
		mSockets.erase(it) ;
}

std::string PqiEchoProbe::linkState(const RsPeerId& peer)
{
	if(!mEnabled)
		return std::string() ;
	RS_STACK_MUTEX(mMtx) ;
	std::map<RsPeerId,uint16_t>::const_iterator p(mPeerIdx.find(peer)) ;
	if(p == mPeerIdx.end())
		return "no socket" ;
	std::map<uint16_t,int>::const_iterator sk(mSockets.find(p->second)) ;
	if(sk == mSockets.end())
		return "no socket" ;
	return snapStr(tcpSnap(sk->second)) ;
}

PqiEchoProbe::TcpSnap PqiEchoProbe::tcpSnap(int fd)
{
	TcpSnap s ;
	if(fd < 0)
		return s ;

	int nd = 0 ;
	socklen_t len = sizeof(nd) ;
	if(getsockopt(fd,IPPROTO_TCP,TCP_NODELAY,(char*)&nd,&len) != 0)
		return s ;
	s.ok = true ;
	s.nodelay = (nd != 0)?1:0 ;

#if defined(__linux__)
	int q = 0 ;
	if(ioctl(fd,TIOCOUTQ,&q) == 0)
		s.sendq = q ;

	struct tcp_info ti ;
	socklen_t tl = sizeof(ti) ;
	if(getsockopt(fd,IPPROTO_TCP,TCP_INFO,&ti,&tl) == 0)
	{
		s.info      = true ;
		s.rtt_us    = ti.tcpi_rtt ;
		s.rttvar_us = ti.tcpi_rttvar ;
		s.ato_us    = ti.tcpi_ato ;
		s.unacked   = ti.tcpi_unacked ;
		s.cwnd      = ti.tcpi_snd_cwnd ;
		s.retrans   = ti.tcpi_total_retrans ;
		s.mss       = ti.tcpi_snd_mss ;
		s.rcv_rtt_us= ti.tcpi_rcv_rtt ;
	}
#elif defined(WINDOWS_SYS) && defined(SIO_TCP_INFO)
	DWORD ver = 0 ;
	TCP_INFO_v0 ti ;
	DWORD got = 0 ;
	if(WSAIoctl((SOCKET)fd,SIO_TCP_INFO,&ver,sizeof(ver),&ti,sizeof(ti),&got,NULL,NULL) == 0)
	{
		s.info    = true ;
		s.sendq   = int64_t(ti.BytesInFlight) ;	// unacknowledged only (Windows does not give the unsent part)
		s.rtt_us  = ti.RttUs ;
		s.cwnd    = ti.Cwnd ;
		s.retrans = uint32_t(ti.BytesRetrans) ;
		s.mss     = ti.Mss ;
	}
#elif defined(SO_NWRITE)
	int q = 0 ;
	socklen_t ql = sizeof(q) ;
	if(getsockopt(fd,SOL_SOCKET,SO_NWRITE,&q,&ql) == 0)
		s.sendq = q ;
#endif
	return s ;
}

std::string PqiEchoProbe::snapStr(const TcpSnap& s)
{
	if(!s.ok)
		return "no socket state" ;

	std::ostringstream o ;
	o << "nodelay=" << (s.nodelay == 1?"on":(s.nodelay == 0?"off":"?")) ;
	o << " sendq=" ;
	if(s.sendq >= 0) o << s.sendq << "B" ; else o << "?" ;
	if(s.info)
	{
		o << std::fixed << std::setprecision(1) << " rtt=" << s.rtt_us/1000.0 << "ms" ;
#if defined(__linux__)
		o << " rttvar=" << s.rttvar_us/1000.0 << "ms ato=" << s.ato_us/1000.0 << "ms rcv_rtt=" << s.rcv_rtt_us/1000.0
		  << "ms unacked=" << s.unacked << "seg cwnd=" << s.cwnd << "seg retrans=" << s.retrans << " mss=" << s.mss ;
#else
		o << " cwnd=" << s.cwnd << "B retrans=" << s.retrans << "B mss=" << s.mss ;
#endif
	}
	return o.str() ;
}
