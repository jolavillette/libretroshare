/*******************************************************************************
 * libretroshare/src/pqi: pqiqosstreamer.cc                                    *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright (C) 2012-2012  Cyril Soler <csoler@users.sourceforge.net>         *
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
#include "pqiqosstreamer.h"
#include "pqiechoprobe.h"

//#define DEBUG_PQIQOSSTREAMER 1

#include "util/rsdebug.h"
#include "util/rsstring.h"

#include <algorithm>

// A turtle tunnel request (or tunnel result) is only useful for a few seconds: the node
// that sent or forwarded a request drops its results once TUNNEL_REQUESTS_RESULT_TIME
// (20 s) has passed since it saw the request, and that delay covers the whole way to the
// destination and back. Sent later, it is at best useless and at worst harmful: a
// request that arrives after a node forgot it is taken for a new one, with a wrong
// origin, and its results leave their route. Over a friend that drains our queue slowly
// such items waited for minutes. They are dropped once they waited more than this:
static const rstime_t PQI_QOS_STALE_TUNNEL_ITEM_AGE = 10 ;	// seconds
static const rstime_t PQI_QOS_STALE_REPORT_PERIOD    = 60 ;	// seconds

// Congestion. Once a second, drain = bytes in our queue / measured out rate: the time the
// friend needs to empty it (the "Drain" column of the bandwidth statistics). A fast file
// transfer keeps up to ~20 s of data in the queue, hence the high threshold.
//  - drain above ENTER_DRAIN for PERSISTENCE seconds in a row: the friend is congested.
//    Only items of priority MIN_PRIORITY and above are queued (heartbeats, bandwidth
//    control, chat, the tunnel requests/results we start or answer ourselves and the
//    GxsTunnel items of the tunnels we are an end of), plus direct mail (see
//    isDirectMailItem()); everything else, relayed turtle traffic included, is dropped,
//    and is purged from the queue when congestion starts.
//  - the congestion lasts at least `hold` seconds, then ends once drain stayed below
//    LEAVE_DRAIN for PERSISTENCE seconds in a row. Purging empties the queue at once, so
//    without this the state would flip every few tens of seconds on a slow friend.
//  - `hold` starts at MIN_HOLD, doubles (up to MAX_HOLD) when congestion comes back less
//    than QUICK_RETURN seconds after it ended, and goes back to MIN_HOLD after CALM_RESET
//    seconds without congestion: a friend that stays slow gets long congestion periods.
static const float    PQI_QOS_CONGESTION_ENTER_DRAIN  = 30.0f ;	// seconds
static const float    PQI_QOS_CONGESTION_LEAVE_DRAIN  = 10.0f ;	// seconds
static const uint32_t PQI_QOS_CONGESTION_PERSISTENCE  = 10 ;	// seconds
static const rstime_t PQI_QOS_CONGESTION_MIN_HOLD     = 60 ;	// seconds
static const rstime_t PQI_QOS_CONGESTION_MAX_HOLD     = 600 ;	// seconds
static const rstime_t PQI_QOS_CONGESTION_QUICK_RETURN = 120 ;	// seconds
static const rstime_t PQI_QOS_CONGESTION_CALM_RESET   = 600 ;	// seconds
static const float    PQI_QOS_CONGESTION_MIN_RATE     = 0.1f ;	// kB/s, floor of the measured out rate
static const int      PQI_QOS_CONGESTION_MIN_PRIORITY = 8 ;

// Serialised item header: version (1 byte), service (2 bytes), subtype (1 byte), size.
// Turtle service 0x0014, subtypes 0x03 (open tunnel) and 0x04 (tunnel ok), see
// turtle/rsturtleitem.h; not included here to keep the pqi layer independent.
static bool isTurtleTunnelRequestOrResult(const void *data,uint32_t size)
{
	if(size < 8)
		return false ;

	const unsigned char *p = (const unsigned char *)data ;

	return p[1] == 0x00 && p[2] == 0x14 && (p[3] == 0x03 || p[3] == 0x04) ;
}

// Direct mail between friends (service 0x0013, see rsitems/rsserviceids.h). p3MsgService
// removes a direct mail from its outbox as soon as it is handed to us, with no receipt:
// dropped here, it would be lost. It is therefore never refused nor purged when the friend
// is congested. It keeps its low priority, so it only uses what chat and the other
// priority 8+ items leave of the link, and it keeps the drain up until it is sent.
static bool isDirectMailItem(const void *data,uint32_t size)
{
	if(size < 8)
		return false ;

	const unsigned char *p = (const unsigned char *)data ;

	return p[1] == 0x00 && p[2] == 0x13 ;
}

const float    pqiQoSstreamer::PQI_QOS_STREAMER_ALPHA      = 2.0f ;

pqiQoSstreamer::pqiQoSstreamer(PQInterface *parent, RsSerialiser *rss, const RsPeerId& peerid, BinInterface *bio_in, int bio_flagsin)
	: pqithreadstreamer(parent,rss,peerid,bio_in,bio_flagsin), pqiQoS(PQI_QOS_STREAMER_MAX_LEVELS, PQI_QOS_STREAMER_ALPHA)
{
	_total_item_size = 0 ;
	_total_item_count = 0 ;

	_congested = false ;
	_congested_since = 0 ;
	_last_congestion_end = 0 ;
	_congestion_hold = PQI_QOS_CONGESTION_MIN_HOLD ;
	_last_congestion_check = 0 ;
	_seconds_above = 0 ;
	_seconds_below = 0 ;
	_last_drain = 0.0f ;
	_last_congestion_report = time(NULL) ;
	_refused_per_priority.resize(PQI_QOS_STREAMER_MAX_LEVELS,0) ;
	_refused_bytes = 0 ;
	_purged = 0 ;

	_last_stale_check = 0 ;
	_last_stale_report = time(NULL) ;
	_stale_dropped = 0 ;
	_stale_dropped_bytes = 0 ;
	_stale_max_age = 0 ;
}

void pqiQoSstreamer::locked_removeStaleTunnelItems()
{
	rstime_t now = time(NULL) ;

	if(now == _last_stale_check)	// once a second is enough
		return ;

	_last_stale_check = now ;

	uint32_t bytes = 0 ;
	rstime_t max_age = 0 ;
	uint32_t n = pqiQoS::removeOldItems(now,PQI_QOS_STALE_TUNNEL_ITEM_AGE,isTurtleTunnelRequestOrResult,bytes,max_age) ;

	if(n > 0)
	{
		_total_item_size -= std::min(bytes,_total_item_size) ;
		_total_item_count -= std::min(n,_total_item_count) ;

		_stale_dropped += n ;
		_stale_dropped_bytes += bytes ;
		_stale_max_age = std::max(_stale_max_age,max_age) ;
	}

	if(now >= _last_stale_report + PQI_QOS_STALE_REPORT_PERIOD)
	{
		if(_stale_dropped > 0)
			RsInfo() << "PQISTREAMER " << PeerId().toStdString() << ": over the last " << (int)(now - _last_stale_report)
			         << " s, " << _stale_dropped << " turtle tunnel requests/results (" << _stale_dropped_bytes
			         << " B) waited more than " << (int)PQI_QOS_STALE_TUNNEL_ITEM_AGE << " s in the out queue and were dropped (oldest "
			         << (int)_stale_max_age << " s)." ;

		_stale_dropped = 0 ;
		_stale_dropped_bytes = 0 ;
		_stale_max_age = 0 ;
		_last_stale_report = now ;
	}
}

void pqiQoSstreamer::locked_tickOutQueue(float out_rate_kBps)
{
	locked_removeStaleTunnelItems() ;	// also while the friend does not read anything
	locked_updateCongestion(out_rate_kBps) ;
}

void pqiQoSstreamer::locked_updateCongestion(float out_rate_kBps)
{
	rstime_t now = time(NULL) ;

	if(now == _last_congestion_check)	// once a second
		return ;

	_last_congestion_check = now ;

	float rate = std::max(out_rate_kBps,PQI_QOS_CONGESTION_MIN_RATE) ;
	float drain = _total_item_size / (rate * 1024.0f) ;
	_last_drain = drain ;

	if(!_congested)
	{
		_seconds_above = (drain > PQI_QOS_CONGESTION_ENTER_DRAIN) ? _seconds_above+1 : 0 ;

		if(_seconds_above >= PQI_QOS_CONGESTION_PERSISTENCE)
		{
			if(_last_congestion_end == 0 || now >= _last_congestion_end + PQI_QOS_CONGESTION_CALM_RESET)
				_congestion_hold = PQI_QOS_CONGESTION_MIN_HOLD ;
			else if(now < _last_congestion_end + PQI_QOS_CONGESTION_QUICK_RETURN)
				_congestion_hold = std::min<rstime_t>(2*_congestion_hold,PQI_QOS_CONGESTION_MAX_HOLD) ;

			uint32_t queue_bytes = _total_item_size ;

			_congested = true ;
			_congested_since = now ;
			_seconds_above = 0 ;
			_seconds_below = 0 ;

			uint32_t bytes = 0 ;
			uint32_t n = pqiQoS::removeLowPriorityItems(PQI_QOS_CONGESTION_MIN_PRIORITY,isDirectMailItem,_refused_per_priority,bytes) ;

			_total_item_size -= std::min(bytes,_total_item_size) ;
			_total_item_count -= std::min(n,_total_item_count) ;
			_refused_bytes += bytes ;
			_purged += n ;

			RsInfo() << "PQISTREAMER congestion ON  for " << PeerId().toStdString() << ": queue " << queue_bytes << " B, out rate "
			         << (int)(1024 * out_rate_kBps) << " B/s, drain " << (int)drain << " s. Queuing priority >= "
			         << PQI_QOS_CONGESTION_MIN_PRIORITY << " only, for at least " << (int)_congestion_hold << " s; "
			         << n << " queued items (" << bytes << " B) purged." ;
		}
	}
	else
	{
		_seconds_below = (drain < PQI_QOS_CONGESTION_LEAVE_DRAIN) ? _seconds_below+1 : 0 ;

		if(now >= _congested_since + _congestion_hold && _seconds_below >= PQI_QOS_CONGESTION_PERSISTENCE)
		{
			_congested = false ;
			_last_congestion_end = now ;
			_seconds_above = 0 ;
			_seconds_below = 0 ;

			RsInfo() << "PQISTREAMER congestion OFF for " << PeerId().toStdString() << " after " << (int)(now - _congested_since)
			         << " s: queue " << _total_item_size << " B, out rate " << (int)(1024 * out_rate_kBps) << " B/s, drain "
			         << (int)drain << " s." ;
		}
	}

	locked_reportCongestion(now) ;
}

void pqiQoSstreamer::locked_reportCongestion(rstime_t now)
{
	if(now < _last_congestion_report + PQI_QOS_STALE_REPORT_PERIOD)
		return ;

	uint32_t total = 0 ;
	std::string per_prio ;

	for(int i=(int)_refused_per_priority.size()-1;i>=0;--i)
		if(_refused_per_priority[i] > 0)
		{
			total += _refused_per_priority[i] ;
			rs_sprintf_append(per_prio," p%d:%u",i,_refused_per_priority[i]) ;
		}

	if(total > 0)
		RsInfo() << "PQISTREAMER congestion for " << PeerId().toStdString() << ": over the last " << (int)(now - _last_congestion_report)
		         << " s, " << total << " items (" << _refused_bytes << " B) not queued, per priority" << per_prio << " ("
		         << _purged << " of them purged from the queue). Now " << (_congested ? "congested" : "not congested")
		         << ", drain " << (int)_last_drain << " s." ;

	std::fill(_refused_per_priority.begin(),_refused_per_priority.end(),0) ;
	_refused_bytes = 0 ;
	_purged = 0 ;
	_last_congestion_report = now ;
}

int pqiQoSstreamer::getQueueSize(bool in) 
{
	if(in)
		return pqistreamer::getQueueSize(in) ;
	else
	{
		RsStackMutex stack(mStreamerMtx); /**** LOCKED MUTEX ****/
		return qos_queue_size() ;
	}
}

//int  pqiQoSstreamer::locked_gatherStatistics(std::vector<uint32_t>& per_service_count,std::vector<uint32_t>& per_priority_count) const // extracting data.
//{
//    return pqiQoS::gatherStatistics(per_service_count,per_priority_count) ;
//}

void pqiQoSstreamer::locked_storeInOutputQueue(void *ptr,int size,int priority)
{
	if(_congested && priority < PQI_QOS_CONGESTION_MIN_PRIORITY && !isDirectMailItem(ptr,size))	// see locked_updateCongestion()
	{
		++_refused_per_priority[std::min(std::max(priority,0),(int)_refused_per_priority.size()-1)] ;
		_refused_bytes += size ;
		free(ptr) ;
		return ;
	}

	_total_item_size += size ;
	++_total_item_count ;

	pqiQoS::in_rsItem(ptr,size,priority) ;
}

void pqiQoSstreamer::locked_clear_out_queue()
{
#ifdef DEBUG_PQIQOSSTREAMER
    if(qos_queue_size() > 0)
	    std::cerr << "  pqiQoSstreamer::locked_clear_out_queue(): clearing " << qos_queue_size() << " pending outqueue elements." << std::endl;
#endif
    
	pqiQoS::clear() ;
	_total_item_size = 0 ;
	_total_item_count = 0 ;

	if(_congested)	// the queue is gone: a new connection starts uncongested
	{
		rstime_t now = time(NULL) ;

		RsInfo() << "PQISTREAMER congestion OFF for " << PeerId().toStdString() << " after " << (int)(now - _congested_since)
		         << " s: out queue cleared." ;

		_congested = false ;
		_last_congestion_end = now ;
		_seconds_above = 0 ;
		_seconds_below = 0 ;
	}
}

void *pqiQoSstreamer::locked_pop_out_data(uint32_t max_slice_size, uint32_t& size, bool& starts, bool& ends, uint32_t& packet_id)
{
	locked_removeStaleTunnelItems() ;

	void *out = pqiQoS::out_rsItem(max_slice_size,size,starts,ends,packet_id) ;

	if(out != NULL && starts && ends)
		PqiEchoProbe::instance().dequeued(PeerId(),out) ;	// debugging probe, off by default: output queue delay

	if(out != NULL) 
	{
		_total_item_size -= size ;
        
        	if(ends)
			--_total_item_count ;
	}

	return out ;
}

