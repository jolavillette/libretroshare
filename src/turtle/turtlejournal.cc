/*******************************************************************************
 * libretroshare/src/turtle: turtlejournal.cc                                  *
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
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "retroshare/rsgossipdiscovery.h"
#include "retroshare/rspeers.h"
#include "retroshare/rsrtt.h"
#include "turtle/rsturtleitem.h"
#include "turtle/turtlejournal.h"

// The echo probe (lib branch debug/peer-echo-probe) knows when a tunnel request
// reached the pqi layer; without it, the processing lag is simply not measured.
#if __has_include("pqi/pqiechoprobe.h")
#	include "pqi/pqiechoprobe.h"
static uint64_t probeTrArrival(uint32_t rid,const TurtlePeerId& from) { return PqiEchoProbe::instance().trArrival(rid,from) ; }
#else
static uint64_t probeTrArrival(uint32_t,const TurtlePeerId&) { return 0 ; }
#endif

static const uint32_t MAX_EVENTS_PER_TUNNEL = 24 ;	// first half kept, last half rolling
static const uint32_t SUMMARY_LAPSE_MS      = 60000 ;
static const uint32_t ITEM_RING_SIZE        = 16 ;      // fingerprints kept per tunnel
static const uint64_t CAPTURE_MS            = 300000 ;  // every item written out for 5 min after the first mismatch
static const uint32_t CAPTURE_MAX_ITEMS     = 3000 ;    // ...but at most this many per tunnel
static const uint64_t FOLLOW_MS             = 1800000 ; // FOLLOW lines until 30 min after the last dropped item
static const uint32_t MAX_BOUNCES_PER_REQ   = 32 ;
static const uint64_t RID_HISTORY_MS        = 9000000 ; // request ids remembered for 2.5 h (longer than the router's 2 h id memory)
static const uint32_t MAX_REBORN_LINES      = 100 ;     // per minute
static const uint32_t MAX_SELFLOOP_LINES    = 100 ;     // per minute

static uint64_t nowMs()
{
	return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
	            std::chrono::system_clock::now().time_since_epoch()).count() ;
}

// Wall clock, printed as UTC, with the raw epoch seconds so that it can be
// matched against the "D <epoch>" lines of the standard retroshare log.

static std::string timeStr(uint64_t ms)
{
	uint64_t s = ms/1000 ;
	std::ostringstream o ;
	o << std::setfill('0')
	  << std::setw(2) << (s/3600)%24 << ':'
	  << std::setw(2) << (s/60)%60   << ':'
	  << std::setw(2) << s%60        << '.'
	  << std::setw(3) << (uint32_t)(ms%1000) ;
	return o.str() ;
}

static std::string hex32(uint32_t v)
{
	std::ostringstream o ;
	o << "0x" << std::hex << std::setw(8) << std::setfill('0') << v ;
	return o.str() ;
}

static const char *itemName(uint8_t subtype)
{
	switch(subtype)
	{
		case RS_TURTLE_SUBTYPE_STRING_SEARCH_REQUEST : return "StringSearchRequest" ;
		case RS_TURTLE_SUBTYPE_FT_SEARCH_RESULT      : return "FileSearchResult" ;
		case RS_TURTLE_SUBTYPE_OPEN_TUNNEL           : return "OpenTunnel" ;
		case RS_TURTLE_SUBTYPE_TUNNEL_OK             : return "TunnelOk" ;
		case RS_TURTLE_SUBTYPE_FILE_REQUEST          : return "FileRequest" ;
		case RS_TURTLE_SUBTYPE_FILE_DATA             : return "FileData" ;
		case RS_TURTLE_SUBTYPE_REGEXP_SEARCH_REQUEST : return "RegExpSearchRequest" ;
		case RS_TURTLE_SUBTYPE_GENERIC_DATA          : return "GenericData" ;
		case RS_TURTLE_SUBTYPE_GENERIC_SEARCH_REQUEST: return "GenericSearchRequest" ;
		case RS_TURTLE_SUBTYPE_GENERIC_SEARCH_RESULT : return "GenericSearchResult" ;
		case RS_TURTLE_SUBTYPE_FILE_MAP              : return "FileMap" ;
		case RS_TURTLE_SUBTYPE_FILE_MAP_REQUEST      : return "FileMapRequest" ;
		case RS_TURTLE_SUBTYPE_CHUNK_CRC             : return "ChunkCrc" ;
		case RS_TURTLE_SUBTYPE_CHUNK_CRC_REQUEST     : return "ChunkCrcRequest" ;
		case RS_TURTLE_SUBTYPE_GENERIC_FAST_DATA     : return "GenericFastData" ;
		default                                      : return "unknown" ;
	}
}

static bool envFlag(const char *name)
{
	const char *v = getenv(name) ;
	return v != NULL && v[0] != '\0' && v[0] != '0' ;
}

static uint32_t envUInt(const char *name,uint32_t def)
{
	const char *v = getenv(name) ;

	if(v == NULL || v[0] == '\0')
		return def ;

	long r = strtol(v,NULL,10) ;
	return (r > 0)?(uint32_t)r:def ;
}

TurtleJournal::ItemDesc TurtleJournal::fingerprint(RsTurtleGenericTunnelItem *item)
{
	ItemDesc d ;
	RsTurtleSerialiser ser ;
	uint32_t size = ser.size(item) ;

	if(size == 0)
		return d ;

	std::vector<uint8_t> buf(size) ;

	if(!ser.serialise(item,buf.data(),&size))
		return d ;

	uint64_t h = 1469598103934665603ULL ;	// FNV-1a 64

	for(uint32_t i=0;i<size;++i)
	{
		h ^= buf[i] ;
		h *= 1099511628211ULL ;
	}
	d.fp   = h ;
	d.size = size ;

	// Generic (fast) data: 8 bytes header, 32 bits tunnel id, 32 bits length, payload.

	uint8_t st = buf[3] ;

	if((st == RS_TURTLE_SUBTYPE_GENERIC_DATA || st == RS_TURTLE_SUBTYPE_GENERIC_FAST_DATA) && size >= 16)
	{
		uint32_t len = (uint32_t(buf[12]) << 24) | (uint32_t(buf[13]) << 16) | (uint32_t(buf[14]) << 8) | uint32_t(buf[15]) ;
		const uint8_t *p = buf.data() + 16 ;

		if(len > size - 16)
			len = size - 16 ;

		if(len >= 20 && p[0] == 0xae && p[1] == 0xad)
		{
			d.payload = ItemDesc::PAYLOAD_ENCRYPTED_FT ;
			d.inner   = uint32_t(p[16]) | (uint32_t(p[17]) << 8) | (uint32_t(p[18]) << 16) | (uint32_t(p[19]) << 24) ;	// little endian
		}
		else if(len >= 8 && p[0] == 0x02)
		{
			d.payload = ItemDesc::PAYLOAD_CLEAR_ITEM ;
			d.inner   = (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]) ;
		}
		else if(len >= 4)
		{
			d.payload = ItemDesc::PAYLOAD_OPAQUE ;
			d.inner   = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]) ;
		}
	}
	return d ;
}

// Inner file transfer items, serialised with their 8 bytes header (ftturtlefiletransferitem.cc):
// file request 24, file map request 16, chunk crc request 16, chunk crc 36,
// file map 20 + 4 per word, file data 24 + chunk size.

std::string TurtleJournal::payloadStr(const ItemDesc& d)
{
	std::ostringstream o ;

	switch(d.payload)
	{
		case ItemDesc::PAYLOAD_ENCRYPTED_FT:
		{
			uint32_t n = d.inner ;
			o << "encrypted-ft inner=" << n << " (" ;
			if(n == 16)      o << "file_map_request or chunk_crc_request" ;
			else if(n == 24) o << "file_request or 1-word file_map" ;
			else if(n == 36) o << "chunk_crc or 4-word file_map" ;
			else if(n >= 1024) o << "file_data, " << (n - 24) << " bytes of file" ;
			else if(n > 20 && (n - 20) % 4 == 0) o << "file_map of " << (n - 20)/4 << " words, or small file_data" ;
			else if(n > 24) o << "file_data, " << (n - 24) << " bytes of file" ;
			else o << "unknown" ;
			o << ")" ;
			break ;
		}
		case ItemDesc::PAYLOAD_CLEAR_ITEM:
			o << "clear item service=0x" << std::hex << std::setw(4) << std::setfill('0') << (d.inner >> 8)
			  << "/0x" << std::setw(2) << (d.inner & 0xff) << std::dec ;
			break ;
		case ItemDesc::PAYLOAD_OPAQUE:
			o << "opaque, starts 0x" << std::hex << std::setw(8) << std::setfill('0') << d.inner << std::dec ;
			break ;
		default:
			break ;
	}
	return o.str() ;
}

static std::string hex64(uint64_t v)
{
	std::ostringstream o ;
	o << std::hex << std::setw(16) << std::setfill('0') << v ;
	return o.str() ;
}

TurtleJournal& TurtleJournal::instance()
{
	static TurtleJournal j ;
	return j ;
}

TurtleJournal::TurtleJournal()
    : mJournalMtx("TurtleJournal"),mLastSummaryMs(0)
{
	mRebornLinesThisLapse   = 0 ;
	mSelfLoopLinesThisLapse = 0 ;
	mTrLagN = mTrLagMax = mTrLagOver5 = 0 ;
	mTrNewMin = mTrNewTotal = 0 ;
	for(uint32_t i=0;i<LM_AGE_BUCKETS;++i)
		mLmMin[i] = mLmTotal[i] = 0 ;
	for(uint32_t i=0;i<TR_AGE_BUCKETS;++i)
		mTrAgeMin[i] = mTrAgeTotal[i] = 0 ;

	mPeers.push_back(TurtlePeerId()) ;	// index 0: null id, i.e. us

	mEnabled        = envFlag("RS_TURTLE_JOURNAL") ;
	mGuard          = envFlag("RS_TURTLE_GUARD") ;
	mVerboseRouting = envFlag("RS_TURTLE_VERBOSE_ROUTING") ;
	mMaxIds         = envUInt("RS_TURTLE_JOURNAL_IDS",100000) ;
	mTtl            = envUInt("RS_TURTLE_JOURNAL_TTL",900) ;

	const char *f = getenv("RS_TURTLE_JOURNAL_FILE") ;
	mFileName = (f != NULL && f[0] != '\0')?std::string(f):std::string("turtle-journal.log") ;

	std::cerr << "(II) TurtleJournal: recorder=" << (mEnabled?"ON":"off")
	          << ", result guard=" << (mGuard?"ON":"off")
	          << ", per-item routing errors=" << (mVerboseRouting?"verbose":"aggregated") ;

	if(mEnabled)
		std::cerr << ", dumping to \"" << mFileName << "\" (max " << mMaxIds << " ids, ttl " << mTtl << "s)" ;

	std::cerr << std::endl ;
}

uint16_t TurtleJournal::peerIdx(const TurtlePeerId& p)
{
	if(p.isNull())
		return 0 ;

	std::map<TurtlePeerId,uint16_t>::const_iterator it(mPeerIdx.find(p)) ;

	if(it != mPeerIdx.end())
		return it->second ;

	if(mPeers.size() >= 0xffff)	// cannot happen with friends only, but stay safe
		return 0 ;

	uint16_t idx = uint16_t(mPeers.size()) ;
	mPeers.push_back(p) ;
	mPeerIdx[p] = idx ;
	return idx ;
}

std::string TurtleJournal::peerStr(uint16_t idx) const
{
	if(idx == 0 || idx >= mPeers.size())
		return "us" ;

	return mPeers[idx].toStdString() ;
}

//=============================================================================//
//                                  Recording                                  //
//=============================================================================//

void TurtleJournal::push(TurtleTunnelId tid,uint8_t kind,uint32_t rid,uint32_t aux,
                         const TurtlePeerId& p1,const TurtlePeerId& p2)
{
	TunnelRecord& rec(mTunnels[tid]) ;

	Event e ;
	e.ms   = nowMs() ;
	e.rid  = rid ;
	e.aux  = aux ;
	e.kind = kind ;
	e.p1   = p1 ;
	e.p2   = p2 ;

	if(rec.first_ms == 0)
		rec.first_ms = e.ms ;

	rec.last_ms = e.ms ;

	// Keep the beginning of the history (how the id was created) and the most
	// recent events (what happened just before the mismatch).

	if(rec.events.size() >= MAX_EVENTS_PER_TUNNEL)
		rec.events.erase(rec.events.begin() + MAX_EVENTS_PER_TUNNEL/2) ;

	rec.events.push_back(e) ;
}

void TurtleJournal::trIn(TurtleTunnelRequestId rid,const TurtlePeerId& from,uint16_t depth,
                         const TurtleFileHash& hash,uint32_t partial_in)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.tr_in ;
	++mTrNewMin ;
	++mTrNewTotal ;

	if(!mEnabled)
		return ;

	uint64_t now = nowMs() ;

	{
		uint64_t arr = probeTrArrival(rid,from) ;
		if(arr != 0 && now > arr)
		{
			uint64_t lag = now - arr ;
			++mTrLagN ;
			if(lag > mTrLagMax) mTrLagMax = lag ;
			if(lag > 5000) ++mTrLagOver5 ;
		}
	}

	// The router only calls this for a request id it does not know (any more). If we
	// accepted the same id before, either the request came back after the router
	// forgot it (same file hash), or two requests share the id (different hash).

	while(!mRidOrder.empty() && mRidOrder.front().first + RID_HISTORY_MS < now)
	{
		std::unordered_map<uint32_t,RidSeen>::iterator h(mRidHistory.find(mRidOrder.front().second)) ;
		if(h != mRidHistory.end() && h->second.first_ms == mRidOrder.front().first)
			mRidHistory.erase(h) ;
		mRidOrder.pop_front() ;
	}

	const uint8_t *hb = hash.toByteArray() ;
	uint32_t hash4 = (uint32_t(hb[0]) << 24) | (uint32_t(hb[1]) << 16) | (uint32_t(hb[2]) << 8) | uint32_t(hb[3]) ;
	uint16_t from_idx = peerIdx(from) ;

	std::unordered_map<uint32_t,RidSeen>::iterator h(mRidHistory.find(rid)) ;

	if(h == mRidHistory.end())
	{
		RidSeen rs ;
		rs.first_ms = rs.last_ms = now ; rs.hash4 = hash4 ; rs.first_from = from_idx ; rs.times = 1 ;
		mRidHistory[rid] = rs ;
		mRidOrder.push_back(std::make_pair(now,rid)) ;
	}
	else
	{
		bool same = (h->second.hash4 == hash4) ;

		if(same) ++mCounters.tr_reborn ; else ++mCounters.tr_rid_collision ;
		if(h->second.times < 0xffff) ++h->second.times ;

		if(mRebornLinesThisLapse < MAX_REBORN_LINES)
		{
			++mRebornLinesThisLapse ;

			std::map<TurtleTunnelRequestId,RequestRecord>::const_iterator old(mRequests.find(rid)) ;

			std::ostringstream o ;
			o << (same?"REBORN ":"RID_COLLISION ") << timeStr(now) << " req=" << hex32(rid) << " hash=" << hash
			  << " accepted as new again from " << peerStr(from_idx) << " depth=" << depth
			  << ", " << (now - h->second.last_ms)/1000 << " s after the previous time, "
			  << (now - h->second.first_ms)/1000 << " s after the first time (first from " << peerStr(h->second.first_from)
			  << ", " << h->second.times << " times now)" ;
			if(old != mRequests.end())
				o << "; previous origin " << old->second.origin ;
			o << std::endl ;
			mPendingDumps.push_back(o.str()) ;
		}
		h->second.last_ms = now ;
	}

	RequestRecord& r(mRequests[rid]) ;

	r.ms         = now ;
	r.origin     = from ;
	r.hash       = hash ;
	r.depth      = depth ;
	r.partial_in = partial_in ;
}

uint32_t TurtleJournal::trAgeBucket(uint32_t age_s)
{
	static const uint32_t limits[TR_AGE_BUCKETS-1] = { 1, 5, 20, 60, 300, 600, 1200, 1800, 3600 } ;
	uint32_t i = 0 ;
	while(i < TR_AGE_BUCKETS-1 && age_s >= limits[i])
		++i ;
	return i ;
}

std::string TurtleJournal::trAgeLine(uint64_t n_new,const uint64_t *ages)
{
	static const char *names[TR_AGE_BUCKETS] = { "<1s","1-5s","5-20s","20-60s","1-5min","5-10min","10-20min","20-30min","30-60min",">60min" } ;
	uint64_t known = 0 ;
	for(uint32_t i=0;i<TR_AGE_BUCKETS;++i)
		known += ages[i] ;
	uint64_t total = known + n_new ;

	std::ostringstream o ;
	o << total << " received, new " << n_new << " (" << std::fixed << std::setprecision(1)
	  << (total ? 100.0*n_new/total : 0.0) << "%), copies of known requests by age of the table entry:" ;
	for(uint32_t i=0;i<TR_AGE_BUCKETS;++i)
		o << " " << names[i] << "=" << ages[i] << " (" << (total ? 100.0*ages[i]/total : 0.0) << "%)" ;
	return o.str() ;
}

void TurtleJournal::trLongMemoryDrop(TurtleTunnelRequestId rid,const TurtlePeerId& from)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	uint32_t b = LM_AGE_BUCKETS-1 ;
	std::unordered_map<uint32_t,RidSeen>::const_iterator h(mRidHistory.find(rid)) ;

	if(h != mRidHistory.end())
	{
		uint64_t now = nowMs() ;
		uint64_t age = (now > h->second.first_ms)?(now - h->second.first_ms)/1000:0 ;
		b = (age < 1800)?0:((age < 2400)?1:((age < 3600)?2:((age < 5400)?3:4))) ;
	}
	++mLmMin[b] ;
	++mLmTotal[b] ;
	++mLmPeersMin[peerIdx(from)] ;
}

std::string TurtleJournal::lmLine(const uint64_t *b)
{
	static const char *names[LM_AGE_BUCKETS] = { "<30min","30-40min","40-60min","60-90min","90-150min","unknown" } ;
	uint64_t n = 0 ;
	for(uint32_t i=0;i<LM_AGE_BUCKETS;++i)
		n += b[i] ;

	std::ostringstream o ;
	o << n << " copies dropped as already seen, by age since first seen:" ;
	for(uint32_t i=0;i<LM_AGE_BUCKETS;++i)
		o << " " << names[i] << "=" << b[i] ;
	return o.str() ;
}

void TurtleJournal::trBounce(TurtleTunnelRequestId rid,const TurtlePeerId& from,const TurtlePeerId& /*known_origin*/,
                             uint32_t age,uint16_t depth,uint32_t partial_in)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.tr_bounce ;
	{
		uint32_t b = trAgeBucket(age) ;
		++mTrAgeMin[b] ;
		++mTrAgeTotal[b] ;
	}

	if(!mEnabled)
		return ;

	// No tunnel id yet: recorded on the request, with the delay in ms, so that
	// a dump can tell whether a peer had this request from somewhere else.

	std::map<TurtleTunnelRequestId,RequestRecord>::iterator it(mRequests.find(rid)) ;

	if(it == mRequests.end())
		return ;

	if(it->second.bounces.size() >= MAX_BOUNCES_PER_REQ)
	{
		++it->second.bounces_dropped ;
		return ;
	}

	Bounce b ;
	uint64_t now = nowMs() ;
	b.dms   = uint32_t((now > it->second.ms)?(now - it->second.ms):0) ;
	b.peer  = peerIdx(from) ;

	{
		PeerTurtleStat& ps(mPeerStats[b.peer]) ;
		++ps.bounces ;
		if(b.dms > 20000) ++ps.slow_bounces ;
		if(b.dms > ps.max_bounce_ms) ps.max_bounce_ms = b.dms ;
	}
	b.depth = depth ;
	b.partial = partial_in ;
	it->second.bounces.push_back(b) ;

	// Every relay perturbs the partial tunnel id with its own secret bias, so a copy
	// coming back with the very value we sent out (or with the value another friend
	// gave us) went through relays that did NOT perturb it. Such relays make tunnel
	// ids independent of the route, i.e. two routes can share a tunnel id.
	if(partial_in != 0)
	{
		const RequestRecord& rr(it->second) ;
		bool echo = (rr.partial_out != 0 && partial_in == rr.partial_out) ;
		bool same = (partial_in == rr.partial_in && from != rr.origin) ;

		if(echo) ++mCounters.partial_echo ;
		if(same) ++mCounters.partial_same ;

		if((echo || same) && mSelfLoopLinesThisLapse < MAX_SELFLOOP_LINES)
		{
			++mSelfLoopLinesThisLapse ;
			std::ostringstream o ;
			o << (echo?"NOPERTURB_ECHO ":"NOPERTURB_SAME ") << timeStr(now) << " req=" << hex32(rid) << " from=" << from
			  << " depth=" << depth << " partial=" << hex32(partial_in) << (echo?" = the value WE sent out":" = the value we got first from ")
			  << (echo?std::string():rr.origin.toStdString()) << " (we received " << hex32(rr.partial_in) << " at depth " << rr.depth
			  << ", sent " << hex32(rr.partial_out) << ")" << std::endl ;
			mPendingDumps.push_back(o.str()) ;
			mPendingPeerInfo.insert(from) ;
		}
	}

	uint64_t arr = probeTrArrival(rid,from) ;
	uint64_t lag = (arr != 0 && now > arr)?(now - arr):0 ;
	if(arr != 0)
	{
		++mTrLagN ;
		if(lag > mTrLagMax) mTrLagMax = lag ;
		if(lag > 5000) ++mTrLagOver5 ;
	}

	// A copy arriving more than a minute after we first saw the request: who held it?
	// Its depth tells how far it travelled; whether we forwarded the request to this
	// friend tells whether the friend had our own copy long before.
	if(b.dms > 60000 && mRebornLinesThisLapse < MAX_REBORN_LINES)
	{
		++mRebornLinesThisLapse ;

		const RequestRecord& r(it->second) ;
		bool fwd_to_it = (std::find(r.fwd_to.begin(),r.fwd_to.end(),b.peer) != r.fwd_to.end()) ;

		std::ostringstream o ;
		o << "LATEBOUNCE " << timeStr(now) << " req=" << hex32(rid) << " from=" << from << " +" << b.dms/1000
		  << "s depth=" << depth << " | we got it first from " << r.origin << " at depth " << r.depth
		  << ", forwarded to " << r.n_fwd << " friends (this one: " << (fwd_to_it?"yes":"NO") << "), "
		  << r.bounces.size()-1 << " earlier copies; reached our pqi layer "
		  << ((arr == 0)?std::string("? (unknown)"):(std::to_string(lag/1000) + "." + std::to_string((lag%1000)/100) + " s before the router processed it"))
		  << std::endl ;
		mPendingDumps.push_back(o.str()) ;
		mPendingPeerInfo.insert(from) ;
	}
}

void TurtleJournal::trFwdTo(TurtleTunnelRequestId rid,const TurtlePeerId& to)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	if(!mEnabled)
		return ;

	std::map<TurtleTunnelRequestId,RequestRecord>::iterator it(mRequests.find(rid)) ;

	if(it != mRequests.end())
		it->second.fwd_to.push_back(peerIdx(to)) ;
}

void TurtleJournal::trFwd(TurtleTunnelRequestId rid,uint32_t partial_out,uint16_t n_peers)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.tr_fwd ;

	if(!mEnabled)
		return ;

	std::map<TurtleTunnelRequestId,RequestRecord>::iterator it(mRequests.find(rid)) ;

	if(it != mRequests.end())
	{
		it->second.partial_out = partial_out ;
		it->second.n_fwd       = n_peers ;
	}
}

void TurtleJournal::trAnswered(TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& to,
                               const TurtleFileHash& hash,bool overwrote,
                               const TurtlePeerId& old_src,const TurtlePeerId& old_dst)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.tr_answered ;

	if(overwrote)
		++mCounters.t_overwrite ;

	if(!mEnabled)
		return ;

	push(tid,TR_ANSWERED,rid,0,to,TurtlePeerId()) ;

	if(overwrote)
		push(tid,T_OVERWRITE,rid,0,old_src,old_dst) ;

	mTunnels[tid].hash = hash ;
}

void TurtleJournal::okIn(TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& from)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.ok_in ;

	if(!mEnabled)
		return ;

	++mPeerStats[peerIdx(from)].ok_in ;

	push(tid,OK_IN,rid,0,from,TurtlePeerId()) ;

	// Bind the tunnel id to the hash and route of its tunnel request, which the
	// router itself does not keep for transit tunnels.

	std::map<TurtleTunnelRequestId,RequestRecord>::const_iterator it(mRequests.find(rid)) ;

	if(it != mRequests.end() && mTunnels[tid].hash.isNull())
		mTunnels[tid].hash = it->second.hash ;

	// The friend the request came from sends us a result for it: the router would
	// store this tunnel with that friend at both ends, and bounce every item of it
	// back to that friend.

	if(it != mRequests.end() && it->second.origin == from)
	{
		++mCounters.ok_from_origin ;
		push(tid,OK_FROM_ORIGIN,rid,0,from,TurtlePeerId()) ;

		if(mSelfLoopLinesThisLapse < MAX_SELFLOOP_LINES)
		{
			++mSelfLoopLinesThisLapse ;
			std::unordered_map<uint32_t,RidSeen>::const_iterator h(mRidHistory.find(rid)) ;

			std::ostringstream o ;
			o << "SELFLOOP " << timeStr(nowMs()) << " tunnel=" << hex32(tid) << " req=" << hex32(rid)
			  << " result received from " << from << ", the friend that sent us this request "
			  << (nowMs() - it->second.ms)/1000 << " s ago" ;
			if(h != mRidHistory.end() && h->second.times > 1)
				o << " (request accepted " << h->second.times << " times, first " << (nowMs() - h->second.first_ms)/1000
				  << " s ago from " << peerStr(h->second.first_from) << ")" ;
			o << std::endl ;
			mPendingDumps.push_back(o.str()) ;
		}

		TunnelRecord& rec(mTunnels[tid]) ;
		if(!rec.dumped)
		{
			rec.dumped = true ;
			dumpTunnel(tid) ;
		}
	}
}

void TurtleJournal::okNoRequest(TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& from)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.ok_no_request ;

	if(mEnabled)
		push(tid,OK_NO_REQUEST,rid,0,from,TurtlePeerId()) ;
}

void TurtleJournal::okTwice(TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& from)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.ok_twice ;

	if(!mEnabled)
		return ;

	uint16_t idx = peerIdx(from) ;
	++mPeerStats[idx].ok_twice ;
	mSuspects[idx] = nowMs() ;

	push(tid,OK_TWICE,rid,0,from,TurtlePeerId()) ;
}

void TurtleJournal::okLate(TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& from,uint32_t age)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.ok_late ;

	if(mEnabled)
	{
		push(tid,OK_LATE,rid,age,from,TurtlePeerId()) ;
		++mPeerStats[peerIdx(from)].ok_late ;
		mTunnels[tid].late_ms = nowMs() ;
	}
}

void TurtleJournal::tunnelCreated(TurtleTunnelId tid,TurtleTunnelRequestId rid,const TurtlePeerId& src,const TurtlePeerId& dst)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.t_create ;

	if(!mEnabled)
		return ;

	++mPeerStats[peerIdx(dst)].t_via ;

	push(tid,T_CREATE,rid,0,src,dst) ;

	// One friend at both ends: every item of this tunnel will be sent back to it.
	if(!src.isNull() && src == dst)
	{
		++mCounters.self_tunnel ;

		if(mSelfLoopLinesThisLapse < MAX_SELFLOOP_LINES)
		{
			++mSelfLoopLinesThisLapse ;
			std::ostringstream o ;
			o << "SELF_TUNNEL " << timeStr(nowMs()) << " tunnel=" << hex32(tid) << " req=" << hex32(rid)
			  << " stored with " << src << " at both ends" << std::endl ;
			mPendingDumps.push_back(o.str()) ;
		}
	}
}

void TurtleJournal::tunnelFound(TurtleTunnelId tid,TurtleTunnelRequestId rid,
                                const TurtlePeerId& stored_src,const TurtlePeerId& stored_dst,
                                const TurtlePeerId& new_src,const TurtlePeerId& new_dst,bool mismatch)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	if(mismatch)
		++mCounters.t_found_mismatch ;
	else
		++mCounters.t_found_match ;

	if(!mEnabled)
		return ;

	push(tid,mismatch?T_FOUND_MISMATCH:T_FOUND_MATCH,rid,0,stored_src,stored_dst) ;

	if(mismatch)
		push(tid,T_FOUND_MISMATCH,rid,1,new_src,new_dst) ;	// aux=1: the incoming pair
}

void TurtleJournal::okForwarded(TurtleTunnelId tid,TurtleTunnelRequestId rid,const TurtlePeerId& to,bool after_mismatch)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	if(after_mismatch)
		++mCounters.ok_fwd_after_mismatch ;

	if(!mEnabled)
		return ;

	push(tid,OK_FWD,rid,after_mismatch?1:0,to,TurtlePeerId()) ;

	// A result for a request we accepted more than once: it goes to the origin of the
	// LATEST generation, possibly not the friend the request first came from.
	{
		std::unordered_map<uint32_t,RidSeen>::const_iterator h(mRidHistory.find(rid)) ;
		if(h != mRidHistory.end() && h->second.times > 1)
		{
			bool rerouted = (peerIdx(to) != h->second.first_from) ;
			++mCounters.reborn_results ;
			if(rerouted) ++mCounters.reborn_results_rerouted ;

			if(mRebornLinesThisLapse < MAX_REBORN_LINES)
			{
				++mRebornLinesThisLapse ;
				std::ostringstream o ;
				o << "REBORN_RESULT " << timeStr(nowMs()) << " tunnel=" << hex32(tid) << " req=" << hex32(rid)
				  << " forwarded to " << to << (rerouted?" — NOT the friend the request first came from (":" — the first origin too (")
				  << peerStr(h->second.first_from) << ", " << (nowMs() - h->second.first_ms)/1000 << " s ago)" << std::endl ;
				mPendingDumps.push_back(o.str()) ;
			}
			TunnelRecord& rec(mTunnels[tid]) ;
			if(!rec.dumped)
			{
				rec.dumped = true ;
				dumpTunnel(tid) ;
			}
		}
	}

	if(after_mismatch)
		mTunnels[tid].announced_after_mismatch = true ;
}

void TurtleJournal::okHeld(TurtleTunnelId tid,TurtleTunnelRequestId rid,const TurtlePeerId& to)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.ok_held ;

	if(mEnabled)
		push(tid,OK_HELD,rid,0,to,TurtlePeerId()) ;
}

void TurtleJournal::itemMismatch(TurtleTunnelId tid,const TurtlePeerId& from,const TurtlePeerId& src,const TurtlePeerId& dst,
                                 uint8_t item_subtype,uint32_t tunnel_age,const ItemDesc& d)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.item_mismatch ;

	if(d.size != 0)
	{
		std::ostringstream k ;
		k << itemName(item_subtype) << " " << d.size << "B" ;
		std::string ps = payloadStr(d) ;
		if(!ps.empty()) k << " " << ps ;
		++mCounters.mismatch_payloads[k.str()] ;
	}
	++mCounters.mismatch_peers[from] ;

	bool first_this_lapse = (mCounters.mismatch_tunnels.find(tid) == mCounters.mismatch_tunnels.end()) ;
	++mCounters.mismatch_tunnels[tid] ;

	if(!mEnabled)
		return ;

	push(tid,ITEM_MISMATCH,0,(uint32_t(item_subtype)<<16) | (tunnel_age & 0xffff),from,src) ;

	TunnelRecord& rec(mTunnels[tid]) ;
	uint64_t now = nowMs() ;

	++rec.mismatch_count ;

	if(first_this_lapse && rec.announced_after_mismatch)
		++mCounters.mismatch_tunnels_announced ;

	uint16_t from_idx = peerIdx(from) ;

	if(!rec.watched)
	{
		rec.watched          = true ;
		rec.src              = src ;
		rec.dst              = dst ;
	}
	rec.last_reject_ms = now ;
	++rec.f_rejected[from_idx] ;

	++mPeerStats[from_idx].drop_from ;
	mSuspects[from_idx] = now ;

	recordItem(tid,rec,now,from_idx,0,item_subtype,d,false) ;

	// The first dropped item is shown in the dump below; capture the following ones.
	if(rec.capture_until_ms == 0)
		rec.capture_until_ms = now + CAPTURE_MS ;

	// One full history per offending tunnel id, not per dropped item.

	if(!rec.dumped)
	{
		rec.dumped = true ;
		dumpTunnel(tid) ;
	}
}

void TurtleJournal::itemRouted(TurtleTunnelId tid,const TurtlePeerId& from,const TurtlePeerId& to,
                               uint8_t item_subtype,const ItemDesc& d)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	if(!mEnabled)
		return ;

	TunnelRecord& rec(mTunnels[tid]) ;
	uint64_t now = nowMs() ;

	if(rec.first_ms == 0)
		rec.first_ms = now ;
	rec.last_ms = now ;

	// A tunnel stored from a result that came too late was not announced upstream:
	// the friend we route its items to does not expect them.
	if(rec.late_ms != 0 && now < rec.late_ms + 600000)
	{
		++mCounters.late_tunnel_items ;
		if(rec.late_items++ == 0)
		{
			++mCounters.late_tunnels_used ;
			if(mSelfLoopLinesThisLapse < MAX_SELFLOOP_LINES)
			{
				++mSelfLoopLinesThisLapse ;
				std::ostringstream o ;
				o << "LATE_TUNNEL_USED " << timeStr(now) << " tunnel=" << hex32(tid) << " stored from a late result "
				  << (now - rec.late_ms)/1000 << " s ago; first item " << itemName(item_subtype) << " size=" << d.size
				  << " from " << peerStr(peerIdx(from)) << " routed to " << peerStr(peerIdx(to)) << std::endl ;
				mPendingDumps.push_back(o.str()) ;
			}
		}
	}

	// We send an item back to the friend it came from: we act as a mirror on this tunnel.
	if(!from.isNull() && from == to)
	{
		++mCounters.mirror_here ;

		if(mSelfLoopLinesThisLapse < MAX_SELFLOOP_LINES)
		{
			++mSelfLoopLinesThisLapse ;
			std::ostringstream o ;
			o << "MIRROR_HERE " << timeStr(now) << " tunnel=" << hex32(tid) << " item=" << itemName(item_subtype)
			  << " size=" << d.size << " sent back to " << from << ", the friend it came from" << std::endl ;
			mPendingDumps.push_back(o.str()) ;
		}
		if(!rec.dumped)
		{
			rec.dumped = true ;
			dumpTunnel(tid) ;
		}
	}

	if(rec.watched)
	{
		if(from.isNull())
			++rec.f_local ;
		else if(from == rec.src)
			++rec.f_from_src ;
		else if(from == rec.dst)
			++rec.f_from_dst ;
	}

	uint16_t from_idx = peerIdx(from) ;

	if(from_idx != 0)
		++mPeerStats[from_idx].acc_from ;

	recordItem(tid,rec,now,from_idx,peerIdx(to),item_subtype,d,true) ;
}

std::string TurtleJournal::copyOf(const TunnelRecord& rec,uint64_t fp,uint16_t from,uint64_t ms) const
{
	if(fp == 0)
		return std::string() ;

	// Earliest earlier item with the same fingerprint. The last ring entry is the
	// item being examined itself when it has just been recorded: skip identical ms+from.

	for(uint32_t i=0;i<rec.ring.size();++i)
	{
		const ItemSeen& s(rec.ring[i]) ;

		if(s.fp != fp || (s.ms == ms && s.from == from))
			continue ;

		std::ostringstream o ;
		o << ((s.from == from)?"  REPEAT of item from ":"  COPY of item from ") << peerStr(s.from)
		  << " (" << (s.accepted?"accepted":"dropped") << ", " << int64_t(ms) - int64_t(s.ms) << " ms earlier)" ;
		return o.str() ;
	}
	return std::string() ;
}

void TurtleJournal::recordItem(TurtleTunnelId tid,TunnelRecord& rec,uint64_t now,uint16_t from,uint16_t to,
                               uint8_t subtype,const ItemDesc& d,bool accepted)
{
	uint64_t fp = d.fp ;
	ItemSeen s ;
	s.ms       = now ;
	s.fp       = fp ;
	s.d        = d ;
	s.from     = from ;
	s.to       = to ;
	s.subtype  = subtype ;
	s.accepted = accepted?1:0 ;

	// Look for an earlier copy before inserting, so that the item does not match itself.
	std::string copy = (now < rec.capture_until_ms && rec.captured < CAPTURE_MAX_ITEMS)?copyOf(rec,fp,from,now):std::string() ;

	if(rec.ring.size() >= ITEM_RING_SIZE)
		rec.ring.erase(rec.ring.begin()) ;
	rec.ring.push_back(s) ;

	if(now < rec.capture_until_ms && rec.captured < CAPTURE_MAX_ITEMS)
	{
		++rec.captured ;

		std::ostringstream o ;
		o << "CAP " << hex32(tid) << " " << timeStr(now) << " " << (accepted?"ACCEPTED":"DROPPED ")
		  << " item=" << itemName(subtype) << " size=" << d.size << " fp=" << hex64(fp)
		  << " from=" << peerStr(from) << " to=" << (accepted?peerStr(to):std::string("-")) << copy ;
		std::string ps = payloadStr(d) ;
		if(!ps.empty())
			o << " [" << ps << "]" ;
		o << std::endl ;
		mPendingDumps.push_back(o.str()) ;
	}
}

void TurtleJournal::itemUnknownTunnel(TurtleTunnelId tid,const TurtlePeerId& from,uint8_t item_subtype,const ItemDesc& d)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.item_unknown_tid ;

	if(mEnabled)
	{
		// What did we know of this id? Closed by us (turtle has no close message, so
		// the other end keeps sending for a while: normal), or never seen in the last
		// 15 min (the sender relays a tunnel we were never told about, e.g. one it
		// stored from a late result without forwarding the result).
		std::map<TurtleTunnelId,TunnelRecord>::const_iterator t(mTunnels.find(tid)) ;
		bool ever_created = false ;
		if(t != mTunnels.end())
			for(uint32_t i=0;i<t->second.events.size() && !ever_created;++i)
				ever_created = (t->second.events[i].kind == T_CREATE || t->second.events[i].kind == T_OVERWRITE
				                || t->second.events[i].kind == T_FOUND_MATCH || t->second.events[i].kind == T_FOUND_MISMATCH) ;

		if(t == mTunnels.end() || (!ever_created && t->second.closed_ms == 0))
		{
			++mCounters.unk_never ;
			++mCounters.unk_never_peers[from] ;
			{
				std::ostringstream k ;
				k << itemName(item_subtype) ;
				if(d.size) k << " " << d.size << "B" ;
				std::string ps = payloadStr(d) ;
				if(!ps.empty()) k << " " << ps ;
				++mCounters.unk_never_kinds[k.str()] ;
			}
			if(mCounters.unk_never_tids.size() < 100000) mCounters.unk_never_tids.insert(tid) ;
		}
		else if(t->second.closed_ms != 0)
		{
			++mCounters.unk_closed ;
			++mCounters.unk_closed_peers[from] ;
		}
		else
			++mCounters.unk_known ;

		push(tid,ITEM_UNKNOWN_TID,0,uint32_t(item_subtype)<<16,from,TurtlePeerId()) ;
	}
}

void TurtleJournal::tunnelClosed(TurtleTunnelId tid,const TurtlePeerId& src,const TurtlePeerId& dst,uint32_t age)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.t_close ;

	if(!mEnabled)
		return ;

	push(tid,T_CLOSE,0,age,src,dst) ;

	TunnelRecord& rec(mTunnels[tid]) ;

	if(rec.closed_ms == 0)
		rec.closed_ms = nowMs() ;	// every tunnel, so that later items on its id are told apart
}

//=============================================================================//
//                                  Reporting                                  //
//=============================================================================//

std::string TurtleJournal::formatEvent(TurtleTunnelId /*tid*/,const Event& e) const
{
	std::ostringstream o ;

	o << "  " << timeStr(e.ms) << "  " ;

	switch(e.kind)
	{
		case TR_BOUNCE:        o << "TR_BOUNCE        req=" << hex32(e.rid) << " from=" << e.p1
		                         << " already known from " << e.p2 << " (" << e.aux << "s ago)" ; break ;
		case TR_ANSWERED:      o << "TR_ANSWERED      req=" << hex32(e.rid) << " we host the hash, replying to " << e.p1 ; break ;
		case T_OVERWRITE:      o << "T_OVERWRITE      the ending tunnel replaced the entry {src=" << e.p1 << ", dst=" << e.p2 << "}" ; break ;
		case OK_IN:            o << "OK_IN            req=" << hex32(e.rid) << " from=" << e.p1 ; break ;
		case OK_NO_REQUEST:    o << "OK_NO_REQUEST    req=" << hex32(e.rid) << " from=" << e.p1 << " (dropped: request unknown)" ; break ;
		case OK_TWICE:         o << "OK_TWICE         req=" << hex32(e.rid) << " from=" << e.p1 << " (dropped: already answered)" ; break ;
		case OK_FROM_ORIGIN:   o << "OK_FROM_ORIGIN   req=" << hex32(e.rid) << " from=" << e.p1 << " (the friend that sent us the request)" ; break ;
		case OK_LATE:          o << "OK_LATE          req=" << hex32(e.rid) << " from=" << e.p1 << " (dropped: request " << e.aux << "s old)" ; break ;
		case T_CREATE:         o << "T_CREATE         req=" << hex32(e.rid) << " {src=" << e.p1 << ", dst=" << e.p2 << "}" ; break ;
		case T_FOUND_MATCH:    o << "T_FOUND_MATCH    req=" << hex32(e.rid) << " id already known, same endpoints {src=" << e.p1 << ", dst=" << e.p2 << "}" ; break ;
		case T_FOUND_MISMATCH: o << "T_FOUND_MISMATCH req=" << hex32(e.rid) << (e.aux?" incoming ":" stored   ")
		                         << "{src=" << e.p1 << ", dst=" << e.p2 << "}" ; break ;
		case OK_FWD:           o << "OK_FWD           req=" << hex32(e.rid) << " result forwarded upstream to " << e.p1
		                         << (e.aux?"   <<<< ROUTE ANNOUNCED WHILE ENDPOINTS DIFFER":"") ; break ;
		case OK_HELD:          o << "OK_HELD          req=" << hex32(e.rid) << " result NOT forwarded to " << e.p1 << " (guard)" ; break ;
		case ITEM_MISMATCH:    o << "ITEM_MISMATCH    item=" << itemName(uint8_t(e.aux>>16)) << " from=" << e.p1
		                         << " (stored src=" << e.p2 << ", tunnel " << (e.aux & 0xffff) << "s old)" ; break ;
		case ITEM_UNKNOWN_TID: o << "ITEM_UNKNOWN_TID item=" << itemName(uint8_t(e.aux>>16)) << " from=" << e.p1 ; break ;
		case T_CLOSE:          o << "T_CLOSE          {src=" << e.p1 << ", dst=" << e.p2 << "} after " << e.aux << "s" ; break ;
		default:               o << "kind=" << (int)e.kind ; break ;
	}

	return o.str() ;
}

void TurtleJournal::dumpTunnel(TurtleTunnelId tid)
{
	const TunnelRecord& rec(mTunnels[tid]) ;

	std::ostringstream o ;

	o << std::endl
	  << "=== tunnel " << hex32(tid) << " : first mismatch, " << rec.events.size()
	  << " recorded events (times are UTC) ===" << std::endl ;

	if(!rec.hash.isNull())
	{
		o << "  hash of the tunnel request that created this id: " << rec.hash ;

		// GRouter hashes are the destination key id, two zero bytes and the client service id
		// (p3GRouter::makeTunnelHash). GxsTunnel hashes are 4 random bytes and the destination
		// GXS id; file transfer hashes look random.
		const uint8_t *hb = rec.hash.toByteArray() ;
		if(hb[16] == 0 && hb[17] == 0)
			o << " (GRouter, client service 0x" << std::hex << std::setw(4) << std::setfill('0') << ((uint32_t(hb[18]) << 8) | hb[19]) << std::dec << ")" ;
		o << std::endl ;
	}

	if(rec.events.size() >= MAX_EVENTS_PER_TUNNEL)
		o << "  (history capped: some intermediate events were dropped)" << std::endl ;

	std::map<TurtleTunnelRequestId,bool> rids ;

	for(uint32_t i=0;i<rec.events.size();++i)
	{
		o << formatEvent(tid,rec.events[i]) << std::endl ;

		if(rec.events[i].rid != 0)
			rids[rec.events[i].rid] = true ;
	}

	// Routing context of every tunnel request involved in this id, as long as
	// it is still in the journal.

	for(std::map<TurtleTunnelRequestId,bool>::const_iterator it(rids.begin());it!=rids.end();++it)
	{
		std::map<TurtleTunnelRequestId,RequestRecord>::const_iterator r(mRequests.find(it->first)) ;

		if(r == mRequests.end())
			continue ;

		const RequestRecord& req(r->second) ;

		o << "  request " << hex32(it->first) << " : from=" << req.origin
		  << " depth=" << req.depth
		  << " hash=" << req.hash
		  << " partial " << hex32(req.partial_in) << " -> " << hex32(req.partial_out)
		  << " forwarded to " << req.n_fwd << " peers"
		  << " (" << timeStr(req.ms) << ")" << std::endl ;

		{
			std::unordered_map<uint32_t,RidSeen>::const_iterator h(mRidHistory.find(it->first)) ;
			if(h != mRidHistory.end() && h->second.times > 1)
				o << "    REBORN request: accepted as new " << h->second.times << " times, first at "
				  << timeStr(h->second.first_ms) << " from " << peerStr(h->second.first_from) << std::endl ;
		}

		mPendingPeerInfo.insert(req.origin) ;

		// For every peer that sent us a result for this request: did we forward the
		// request to it, and did it send us the request itself (a bounce)? A peer that
		// had the request from somewhere else first is not supposed to send us a result.

		std::set<TurtlePeerId> responders ;

		for(uint32_t i=0;i<rec.events.size();++i)
			if(rec.events[i].rid == it->first && (rec.events[i].kind == OK_IN || rec.events[i].kind == OK_TWICE))
				responders.insert(rec.events[i].p1) ;

		for(std::set<TurtlePeerId>::const_iterator p(responders.begin());p!=responders.end();++p)
		{
			std::map<TurtlePeerId,uint16_t>::const_iterator pi(mPeerIdx.find(*p)) ;
			uint16_t idx = (pi == mPeerIdx.end())?0xffff:pi->second ;

			bool fwd = (std::find(req.fwd_to.begin(),req.fwd_to.end(),idx) != req.fwd_to.end()) ;

			o << "    responder " << *p << ": request forwarded to it: " << (fwd?"yes":"NO")
			  << ", request received from it: " ;

			if(*p == req.origin)
				o << "it is the ORIGIN" ;
			else
			{
				bool any = false ;

				for(uint32_t b=0;b<req.bounces.size();++b)
					if(req.bounces[b].peer == idx)
					{
						o << (any?", ":"") << "bounce +" << req.bounces[b].dms << " ms depth " << req.bounces[b].depth ;
						any = true ;
					}

				if(!any)
					o << "never" << (req.bounces_dropped?" (bounce list capped)":"") ;
			}
			o << std::endl ;

			mPendingPeerInfo.insert(*p) ;
		}

		o << "    forwarded to:" ;
		for(uint32_t i=0;i<req.fwd_to.size();++i)
			o << " " << peerStr(req.fwd_to[i]).substr(0,8) ;
		o << std::endl ;

		o << "    bounces (" << req.bounces.size() << (req.bounces_dropped?"+":"") << "):" ;
		for(uint32_t i=0;i<req.bounces.size();++i)
			o << " " << peerStr(req.bounces[i].peer).substr(0,8) << "@+" << req.bounces[i].dms << "ms/d" << req.bounces[i].depth ;
		o << std::endl ;
	}

	// Items seen on this tunnel just before and at the first mismatch.

	o << "  last items on this tunnel (fingerprint = hash of the serialised item):" << std::endl ;

	for(uint32_t i=0;i<rec.ring.size();++i)
	{
		const ItemSeen& s(rec.ring[i]) ;

		o << "    " << timeStr(s.ms) << " " << (s.accepted?"ACCEPTED":"DROPPED ") << " item=" << itemName(s.subtype)
		  << " size=" << s.d.size << " fp=" << hex64(s.fp) << " from=" << peerStr(s.from) << " to=" << (s.accepted?peerStr(s.to):std::string("-"))
		  << copyOf(rec,s.fp,s.from,s.ms) ;
		std::string ps = payloadStr(s.d) ;
		if(!ps.empty())
			o << " [" << ps << "]" ;
		o << std::endl ;
	}

	for(uint32_t i=0;i<rec.events.size();++i)
		if(rec.events[i].kind == ITEM_MISMATCH || rec.events[i].kind == OK_TWICE || rec.events[i].kind == T_CREATE)
		{
			mPendingPeerInfo.insert(rec.events[i].p1) ;
			if(rec.events[i].kind == T_CREATE)
				mPendingPeerInfo.insert(rec.events[i].p2) ;
		}

	o << "  every item of this tunnel is logged as CAP lines for " << CAPTURE_MS/1000
	  << " s, then one FOLLOW line per minute until " << FOLLOW_MS/60000 << " min after the last dropped item." << std::endl ;

	mPendingDumps.push_back(o.str()) ;
}

void TurtleJournal::followLines(uint64_t now,std::ostringstream& o)
{
	for(std::map<TurtleTunnelId,TunnelRecord>::iterator it(mTunnels.begin());it!=mTunnels.end();++it)
	{
		TunnelRecord& rec(it->second) ;

		if(!rec.watched)
			continue ;

		o << "FOLLOW " << hex32(it->first) << " " << timeStr(now) << " last minute: from src=" << rec.f_from_src
		  << " from dst=" << rec.f_from_dst << " emitted by us=" << rec.f_local << ", dropped:" ;

		if(rec.f_rejected.empty())
			o << " none" ;

		for(std::map<uint16_t,uint32_t>::const_iterator r(rec.f_rejected.begin());r!=rec.f_rejected.end();++r)
			o << " " << peerStr(r->first) << "=" << r->second ;

		o << ", our entry: " ;

		if(rec.closed_ms)
			o << "expired " << (now - rec.closed_ms)/1000 << " s ago" ;
		else
			o << "alive" ;

		o << " (src=" << rec.src << " dst=" << rec.dst << ")" << std::endl ;

		rec.f_from_src = rec.f_from_dst = rec.f_local = 0 ;
		rec.f_rejected.clear() ;

		if(now > rec.last_reject_ms + FOLLOW_MS)
		{
			o << "FOLLOW " << hex32(it->first) << " ends: no dropped item for " << FOLLOW_MS/60000 << " min." << std::endl ;
			rec.watched = false ;
		}
	}
}

void TurtleJournal::sweep(uint64_t now_ms)
{
	uint64_t limit = (now_ms > (uint64_t)mTtl*1000)?(now_ms - (uint64_t)mTtl*1000):0 ;

	for(std::map<TurtleTunnelId,TunnelRecord>::iterator it(mTunnels.begin());it!=mTunnels.end();)
		if(it->second.last_ms < limit && !it->second.watched)
			it = mTunnels.erase(it) ;
		else
			++it ;

	for(std::map<TurtleTunnelRequestId,RequestRecord>::iterator it(mRequests.begin());it!=mRequests.end();)
		if(it->second.ms < limit)
			it = mRequests.erase(it) ;
		else
			++it ;

	// Hard cap: drop the least recently touched records first.

	while(mTunnels.size() > mMaxIds)
	{
		std::map<TurtleTunnelId,TunnelRecord>::iterator oldest(mTunnels.begin()) ;

		for(std::map<TurtleTunnelId,TunnelRecord>::iterator it(mTunnels.begin());it!=mTunnels.end();++it)
			if(!it->second.watched && (oldest->second.watched || it->second.last_ms < oldest->second.last_ms))
				oldest = it ;

		if(oldest->second.watched)	// only watched records left
			break ;

		mTunnels.erase(oldest) ;
	}
}

void TurtleJournal::tick(uint32_t live_tunnels,uint32_t live_requests)
{
	std::vector<std::string> dumps ;
	std::string              summary ;
	std::string              follow ;
	std::string              file_name ;
	bool                     enabled ;
	std::set<TurtlePeerId>   peers_to_name ;
	std::vector<std::pair<TurtlePeerId,PeerTurtleStat> > suspects ;
	uint64_t                 tick_now = 0 ;

	{
		RS_STACK_MUTEX(mJournalMtx) ;

		uint64_t now = nowMs() ;

		enabled   = mEnabled ;
		file_name = mFileName ;

		dumps.swap(mPendingDumps) ;

		if(mLastSummaryMs == 0)
			mLastSummaryMs = now ;

		for(std::set<TurtlePeerId>::const_iterator it(mPendingPeerInfo.begin());it!=mPendingPeerInfo.end();++it)
			if(!it->isNull() && mPeerInfoDone.insert(*it).second)
				peers_to_name.insert(*it) ;
		mPendingPeerInfo.clear() ;

		if(now >= mLastSummaryMs + SUMMARY_LAPSE_MS)
		{
			sweep(now) ;

			if(mEnabled)
			{
				std::ostringstream fo ;
				followLines(now,fo) ;
				follow = fo.str() ;

				// Suspect peers: their minute of turtle activity, resolved off mutex below.

				// How late the router processes tunnel requests after they reach pqi.
				{
					std::ostringstream lo ;
					lo << "TRLAG " << timeStr(now) << " last minute: " << mTrLagN << " tunnel requests timed, max "
					   << mTrLagMax << " ms between pqi arrival and router processing, " << mTrLagOver5 << " over 5 s" << std::endl ;
					mPendingDumps.push_back(lo.str()) ;
					mTrLagN = mTrLagMax = mTrLagOver5 = 0 ;
				}

				// Received tunnel requests: share of new ones, and age of the known ones.
				{
					std::ostringstream ao ;
					ao << "TRAGE " << timeStr(now) << " last minute: " << trAgeLine(mTrNewMin,mTrAgeMin) << std::endl ;
					ao << "TRAGE " << timeStr(now) << " since start: " << trAgeLine(mTrNewTotal,mTrAgeTotal) << std::endl ;

					// Copies the router dropped thanks to its long memory of request ids.
					ao << "TRLM " << timeStr(now) << " last minute: " << lmLine(mLmMin) ;
					if(!mLmPeersMin.empty())
					{
						std::vector<std::pair<uint64_t,uint16_t> > top ;
						for(std::map<uint16_t,uint64_t>::const_iterator p(mLmPeersMin.begin());p!=mLmPeersMin.end();++p)
							top.push_back(std::make_pair(p->second,p->first)) ;
						std::sort(top.rbegin(),top.rend()) ;
						ao << "; brought by:" ;
						for(uint32_t i=0;i<top.size() && i<3;++i)
							ao << " " << mPeers[top[i].second] << "=" << top[i].first ;
					}
					ao << std::endl ;
					ao << "TRLM " << timeStr(now) << " since start: " << lmLine(mLmTotal) << std::endl ;
					for(uint32_t i=0;i<LM_AGE_BUCKETS;++i)
						mLmMin[i] = 0 ;
					mLmPeersMin.clear() ;
					mPendingDumps.push_back(ao.str()) ;
					mTrNewMin = 0 ;
					for(uint32_t i=0;i<TR_AGE_BUCKETS;++i)
						mTrAgeMin[i] = 0 ;
				}

				// Friends delivering requests or results late (slow or Tor links).

				for(std::map<uint16_t,PeerTurtleStat>::const_iterator ps(mPeerStats.begin());ps!=mPeerStats.end();++ps)
					if(ps->first != 0 && (ps->second.slow_bounces > 0 || ps->second.ok_late > 0))
					{
						std::ostringstream so ;
						so << "SLOWPEER " << timeStr(now) << " " << mPeers[ps->first] << " last minute: requests bounced to us "
						   << ps->second.bounces << " (" << ps->second.slow_bounces << " more than 20 s after we first saw them, max "
						   << ps->second.max_bounce_ms/1000 << " s), late results " << ps->second.ok_late << std::endl ;
						mPendingDumps.push_back(so.str()) ;
						mPendingPeerInfo.insert(mPeers[ps->first]) ;
					}

				for(std::map<uint16_t,uint64_t>::iterator it(mSuspects.begin());it!=mSuspects.end();)
					if(now > it->second + FOLLOW_MS)
						it = mSuspects.erase(it) ;
					else
					{
						suspects.push_back(std::make_pair(mPeers[it->first],mPeerStats[it->first])) ;
						++it ;
					}

				mPeerStats.clear() ;
				tick_now = now ;
			}

			const Counters& c(mCounters) ;

			if(c.item_mismatch || c.item_unknown_tid || c.ok_twice || c.t_found_mismatch || c.ok_held || c.tr_reborn || c.ok_from_origin || c.mirror_here || c.self_tunnel || c.late_tunnel_items || c.partial_echo || c.partial_same || c.reborn_results)
			{
				std::ostringstream o ;

				o << "(WW) TURTLE-JOURNAL over the last " << (now-mLastSummaryMs)/1000 << "s: "
				  << "dropped items: " << c.item_mismatch << " mismatching (on "
				  << c.mismatch_tunnels.size() << " distinct tunnel ids" ;

				if(mEnabled)
					o << ", " << c.mismatch_tunnels_announced << " of which we had announced upstream" ;

				o << "), " << c.item_unknown_tid << " on unknown ids. "
				  << "Tunnel results: " << c.ok_in << " in, " << c.t_create << " new tunnels, "
				  << c.t_found_match << " known id/same endpoints, " << c.t_found_mismatch
				  << " known id/DIFFERENT endpoints (" << c.ok_fwd_after_mismatch << " forwarded upstream, "
				  << c.ok_held << " held by the guard), " << c.ok_twice << " duplicate, "
				  << c.ok_late << " late, " << c.ok_no_request << " orphan. "
				  << "Tunnel requests: " << c.tr_in << " in, " << c.tr_bounce << " bouncing, "
				  << c.tr_answered << " answered here (" << c.t_overwrite << " overwriting an existing id), "
				  << c.tr_reborn << " reborn (accepted again after the router forgot them), " << c.tr_rid_collision << " id collisions. "
				  << "Results from the request's own origin: " << c.ok_from_origin << ", tunnels stored with one friend at both ends: "
				  << c.self_tunnel << ", items bounced back to their sender: " << c.mirror_here
				  << ", items routed on tunnels stored from a late result: " << c.late_tunnel_items << " (" << c.late_tunnels_used << " tunnels)"
				  << ", request copies with an unperturbed partial id: " << c.partial_echo << " echoing ours, " << c.partial_same << " same as another friend's"
				  << ", results for reborn requests: " << c.reborn_results << " (" << c.reborn_results_rerouted << " sent to another friend than the first origin). "
				  << "Tables: " << live_tunnels << " tunnels, " << live_requests << " requests, "
				  << c.t_close << " tunnels closed." ;

				if(c.item_unknown_tid > 0 && mEnabled)
				{
					std::vector<std::pair<uint64_t,TurtlePeerId> > tn,tc ;
					for(std::map<TurtlePeerId,uint64_t>::const_iterator it(c.unk_never_peers.begin());it!=c.unk_never_peers.end();++it) tn.push_back(std::make_pair(it->second,it->first)) ;
					for(std::map<TurtlePeerId,uint64_t>::const_iterator it(c.unk_closed_peers.begin());it!=c.unk_closed_peers.end();++it) tc.push_back(std::make_pair(it->second,it->first)) ;
					std::sort(tn.rbegin(),tn.rend()) ;
					std::sort(tc.rbegin(),tc.rend()) ;

					o << " Unknown ids: " << c.unk_never << " items on " << c.unk_never_tids.size() << " ids never seen (top senders:" ;
					for(uint32_t i=0;i<tn.size() && i<3;++i) o << " " << tn[i].second << "=" << tn[i].first ;
					// how long have these ids been sending to us? (first unknown item seen, kept 15 min)
					{
						std::vector<uint64_t> ages ;
						for(std::set<TurtleTunnelId>::const_iterator t(c.unk_never_tids.begin());t!=c.unk_never_tids.end();++t)
						{
							std::map<TurtleTunnelId,TunnelRecord>::const_iterator r(mTunnels.find(*t)) ;
							if(r != mTunnels.end() && !r->second.events.empty())
								ages.push_back((now > r->second.events.front().ms)?(now - r->second.events.front().ms)/1000:0) ;
						}
						std::sort(ages.begin(),ages.end()) ;
						if(!ages.empty())
						{
							uint32_t over5 = 0 ;
							for(uint32_t i=0;i<ages.size();++i) if(ages[i] > 300) ++over5 ;
							o << "; first unknown item on those ids: median " << ages[ages.size()/2] << " s ago, max " << ages.back()
							  << " s, " << over5 << " ids for more than 5 min" ;
						}
						std::vector<std::pair<uint64_t,std::string> > kinds ;
						for(std::map<std::string,uint64_t>::const_iterator k(c.unk_never_kinds.begin());k!=c.unk_never_kinds.end();++k)
							kinds.push_back(std::make_pair(k->second,k->first)) ;
						std::sort(kinds.rbegin(),kinds.rend()) ;
						o << "; they carry:" ;
						for(uint32_t i=0;i<kinds.size() && i<4;++i) o << " [" << kinds[i].second << "]=" << kinds[i].first ;
					}
					o << "), " << c.unk_closed << " after we closed the tunnel (top:" ;
					for(uint32_t i=0;i<tc.size() && i<3;++i) o << " " << tc[i].second << "=" << tc[i].first ;
					o << "), " << c.unk_known << " other." ;
				}

				if(!c.mismatch_peers.empty())
				{
					// The three peers sending most of the dropped items.

					std::vector<std::pair<uint64_t,TurtlePeerId> > top ;

					for(std::map<TurtlePeerId,uint64_t>::const_iterator it(c.mismatch_peers.begin());it!=c.mismatch_peers.end();++it)
						top.push_back(std::make_pair(it->second,it->first)) ;

					std::sort(top.rbegin(),top.rend()) ;

					if(!c.mismatch_payloads.empty())
					{
						std::vector<std::pair<uint64_t,std::string> > kinds ;
						for(std::map<std::string,uint64_t>::const_iterator it(c.mismatch_payloads.begin());it!=c.mismatch_payloads.end();++it)
							kinds.push_back(std::make_pair(it->second,it->first)) ;
						std::sort(kinds.rbegin(),kinds.rend()) ;

						o << " Dropped items carry:" ;
						for(uint32_t i=0;i<kinds.size() && i<5;++i)
							o << " [" << kinds[i].second << "]=" << kinds[i].first ;
						o << "." ;
					}

					o << " Top senders of dropped items:" ;

					for(uint32_t i=0;i<top.size() && i<3;++i)
						o << " " << top[i].second << "=" << top[i].first ;
				}

				summary = o.str() ;
			}

			mCounters.clear() ;
			mRebornLinesThisLapse = 0 ;
			mSelfLoopLinesThisLapse = 0 ;
			mLastSummaryMs = now ;
		}
	}

	// Off mutex: file and console output.

	if(!summary.empty())
		std::cerr << summary << std::endl ;

	if(!enabled || (dumps.empty() && summary.empty() && follow.empty() && peers_to_name.empty() && suspects.empty()))
		return ;

	// Suspect peers: link state, RTT and clock offset, turtle activity. Off both mutexes.

	std::ostringstream pstate ;

	for(uint32_t i=0;i<suspects.size();++i)
	{
		const TurtlePeerId& id(suspects[i].first) ;
		const PeerTurtleStat& st(suspects[i].second) ;

		int online = rsPeers ? (rsPeers->isOnline(id)?1:0) : -1 ;

		std::map<TurtlePeerId,int>::iterator lo(mLastOnline.find(id)) ;
		int before = (lo == mLastOnline.end())?-1:lo->second ;
		mLastOnline[id] = online ;

		pstate << "PEERSTATE " << timeStr(tick_now) << " " << id << " online=" << ((online == 1)?"yes":((online == 0)?"NO":"?")) ;

		if(before != -1 && before != online)
			pstate << " (went " << ((online == 1)?"ONLINE":"OFFLINE") << " during the last minute)" ;

		std::list<RsRttPongResult> pongs ;

		if(rsRtt && rsRtt->getPongResults(id,1,pongs) > 0 && !pongs.empty())
		{
			const RsRttPongResult& p(pongs.back()) ;
			double age = double(tick_now)/1000.0 - p.mTS ;

			pstate << std::fixed << std::setprecision(3) << " rtt=" << p.mRTT << "s offset=" << p.mOffset
			       << "s (pong " << std::setprecision(0) << age << " s ago)" ;
		}
		else
			pstate << " rtt=?" ;

		pstate << " | turtle last minute: results from it=" << st.ok_in << " (duplicates=" << st.ok_twice
		       << "), tunnels created through it=" << st.t_via << ", items accepted from it=" << st.acc_from
		       << ", items dropped from it=" << st.drop_from << std::endl ;
	}

	// Name and announced version of the peers involved, once per peer and per run.
	// Off both mutexes: this calls into rsPeers and the gossip discovery service.

	std::ostringstream pinfo ;

	for(std::set<TurtlePeerId>::const_iterator it(peers_to_name.begin());it!=peers_to_name.end();++it)
	{
		std::string name = rsPeers ? rsPeers->getPeerName(*it) : std::string() ;
		std::string version ;

		if(!rsGossipDiscovery || !rsGossipDiscovery->getPeerVersion(*it,version))
			version = "unknown" ;

		pinfo << "PEER " << *it << " name=\"" << name << "\" version=\"" << version << "\""
		      << (name.empty()?" (not a direct friend)":"") << std::endl ;
	}

	std::ofstream f(file_name.c_str(),std::ios::app) ;

	if(!f)
		return ;

	for(uint32_t i=0;i<dumps.size();++i)
		f << dumps[i] ;

	f << pinfo.str() << follow << pstate.str() ;

	if(!summary.empty())
		f << summary << std::endl ;
}
