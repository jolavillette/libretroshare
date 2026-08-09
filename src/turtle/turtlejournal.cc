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

#include "turtle/rsturtleitem.h"
#include "turtle/turtlejournal.h"

static const uint32_t MAX_EVENTS_PER_TUNNEL = 24 ;	// first half kept, last half rolling
static const uint32_t SUMMARY_LAPSE_MS      = 60000 ;

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

TurtleJournal& TurtleJournal::instance()
{
	static TurtleJournal j ;
	return j ;
}

TurtleJournal::TurtleJournal()
    : mJournalMtx("TurtleJournal"),mLastSummaryMs(0)
{
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

	if(!mEnabled)
		return ;

	RequestRecord& r(mRequests[rid]) ;

	r.ms         = nowMs() ;
	r.origin     = from ;
	r.hash       = hash ;
	r.depth      = depth ;
	r.partial_in = partial_in ;
}

void TurtleJournal::trBounce(TurtleTunnelRequestId rid,const TurtlePeerId& from,const TurtlePeerId& known_origin,uint32_t age)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.tr_bounce ;

	if(!mEnabled)
		return ;

	// No tunnel id yet: recorded on the request only. Kept as an event on the
	// pseudo id 0 so that it shows up in the request section of the dumps.
	push(0,TR_BOUNCE,rid,age,from,known_origin) ;
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

	push(tid,OK_IN,rid,0,from,TurtlePeerId()) ;

	// Bind the tunnel id to the hash and route of its tunnel request, which the
	// router itself does not keep for transit tunnels.

	std::map<TurtleTunnelRequestId,RequestRecord>::const_iterator it(mRequests.find(rid)) ;

	if(it != mRequests.end() && mTunnels[tid].hash.isNull())
		mTunnels[tid].hash = it->second.hash ;
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

	if(mEnabled)
		push(tid,OK_TWICE,rid,0,from,TurtlePeerId()) ;
}

void TurtleJournal::okLate(TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& from,uint32_t age)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.ok_late ;

	if(mEnabled)
		push(tid,OK_LATE,rid,age,from,TurtlePeerId()) ;
}

void TurtleJournal::tunnelCreated(TurtleTunnelId tid,TurtleTunnelRequestId rid,const TurtlePeerId& src,const TurtlePeerId& dst)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.t_create ;

	if(mEnabled)
		push(tid,T_CREATE,rid,0,src,dst) ;
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
                                 uint8_t item_subtype,uint32_t tunnel_age)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.item_mismatch ;
	++mCounters.mismatch_peers[from] ;

	bool first_this_lapse = (mCounters.mismatch_tunnels.find(tid) == mCounters.mismatch_tunnels.end()) ;
	++mCounters.mismatch_tunnels[tid] ;

	if(!mEnabled)
		return ;

	push(tid,ITEM_MISMATCH,0,(uint32_t(item_subtype)<<16) | (tunnel_age & 0xffff),from,src) ;

	TunnelRecord& rec(mTunnels[tid]) ;

	++rec.mismatch_count ;

	if(first_this_lapse && rec.announced_after_mismatch)
		++mCounters.mismatch_tunnels_announced ;

	// One full history per offending tunnel id, not per dropped item.

	if(!rec.dumped)
	{
		rec.dumped = true ;
		dumpTunnel(tid) ;
	}
}

void TurtleJournal::itemUnknownTunnel(TurtleTunnelId tid,const TurtlePeerId& from,uint8_t item_subtype)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.item_unknown_tid ;

	if(mEnabled)
		push(tid,ITEM_UNKNOWN_TID,0,uint32_t(item_subtype)<<16,from,TurtlePeerId()) ;
}

void TurtleJournal::tunnelClosed(TurtleTunnelId tid,const TurtlePeerId& src,const TurtlePeerId& dst,uint32_t age)
{
	RS_STACK_MUTEX(mJournalMtx) ;

	++mCounters.t_close ;

	if(mEnabled)
		push(tid,T_CLOSE,0,age,src,dst) ;
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
		o << "  hash of the tunnel request that created this id: " << rec.hash << std::endl ;

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

		o << "  request " << hex32(it->first) << " : from=" << r->second.origin
		  << " depth=" << r->second.depth
		  << " hash=" << r->second.hash
		  << " partial " << hex32(r->second.partial_in) << " -> " << hex32(r->second.partial_out)
		  << " forwarded to " << r->second.n_fwd << " peers"
		  << " (" << timeStr(r->second.ms) << ")" << std::endl ;
	}

	mPendingDumps.push_back(o.str()) ;
}

void TurtleJournal::sweep(uint64_t now_ms)
{
	uint64_t limit = (now_ms > (uint64_t)mTtl*1000)?(now_ms - (uint64_t)mTtl*1000):0 ;

	for(std::map<TurtleTunnelId,TunnelRecord>::iterator it(mTunnels.begin());it!=mTunnels.end();)
		if(it->second.last_ms < limit)
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
			if(it->second.last_ms < oldest->second.last_ms)
				oldest = it ;

		mTunnels.erase(oldest) ;
	}
}

void TurtleJournal::tick(uint32_t live_tunnels,uint32_t live_requests)
{
	std::vector<std::string> dumps ;
	std::string              summary ;
	std::string              file_name ;
	bool                     enabled ;

	{
		RS_STACK_MUTEX(mJournalMtx) ;

		uint64_t now = nowMs() ;

		enabled   = mEnabled ;
		file_name = mFileName ;

		dumps.swap(mPendingDumps) ;

		if(mLastSummaryMs == 0)
			mLastSummaryMs = now ;

		if(now >= mLastSummaryMs + SUMMARY_LAPSE_MS)
		{
			sweep(now) ;

			const Counters& c(mCounters) ;

			if(c.item_mismatch || c.item_unknown_tid || c.ok_twice || c.t_found_mismatch || c.ok_held)
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
				  << c.tr_answered << " answered here (" << c.t_overwrite << " overwriting an existing id). "
				  << "Tables: " << live_tunnels << " tunnels, " << live_requests << " requests, "
				  << c.t_close << " tunnels closed." ;

				if(!c.mismatch_peers.empty())
				{
					// The three peers sending most of the dropped items.

					std::vector<std::pair<uint64_t,TurtlePeerId> > top ;

					for(std::map<TurtlePeerId,uint64_t>::const_iterator it(c.mismatch_peers.begin());it!=c.mismatch_peers.end();++it)
						top.push_back(std::make_pair(it->second,it->first)) ;

					std::sort(top.rbegin(),top.rend()) ;

					o << " Top senders of dropped items:" ;

					for(uint32_t i=0;i<top.size() && i<3;++i)
						o << " " << top[i].second << "=" << top[i].first ;
				}

				summary = o.str() ;
			}

			mCounters.clear() ;
			mLastSummaryMs = now ;
		}
	}

	// Off mutex: file and console output.

	if(!summary.empty())
		std::cerr << summary << std::endl ;

	if(!enabled || (dumps.empty() && summary.empty()))
		return ;

	std::ofstream f(file_name.c_str(),std::ios::app) ;

	if(!f)
		return ;

	for(uint32_t i=0;i<dumps.size();++i)
		f << dumps[i] ;

	if(!summary.empty())
		f << summary << std::endl ;
}
