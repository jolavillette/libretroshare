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

//#define DEBUG_PQIQOSSTREAMER 1

#include "util/rsdebug.h"

#include <algorithm>

// A turtle tunnel request (or tunnel result) is only useful for a few seconds: its
// results are only accepted for TUNNEL_REQUESTS_RESULT_TIME (20 s) by the node that
// forwarded it. Sent later, it is at best useless and at worst harmful: a request that
// arrives after a node forgot it is taken for a new one, with a wrong origin, and its
// results leave their route. Over a friend that drains our queue slowly such items
// waited for minutes. They are dropped once they waited more than this:
static const rstime_t PQI_QOS_STALE_TUNNEL_ITEM_AGE = 20 ;	// seconds
static const rstime_t PQI_QOS_STALE_REPORT_PERIOD    = 60 ;	// seconds

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

const float    pqiQoSstreamer::PQI_QOS_STREAMER_ALPHA      = 2.0f ;

pqiQoSstreamer::pqiQoSstreamer(PQInterface *parent, RsSerialiser *rss, const RsPeerId& peerid, BinInterface *bio_in, int bio_flagsin)
	: pqithreadstreamer(parent,rss,peerid,bio_in,bio_flagsin), pqiQoS(PQI_QOS_STREAMER_MAX_LEVELS, PQI_QOS_STREAMER_ALPHA)
{
	_total_item_size = 0 ;
	_total_item_count = 0 ;

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
}

void *pqiQoSstreamer::locked_pop_out_data(uint32_t max_slice_size, uint32_t& size, bool& starts, bool& ends, uint32_t& packet_id)
{
	locked_removeStaleTunnelItems() ;

	void *out = pqiQoS::out_rsItem(max_slice_size,size,starts,ends,packet_id) ;

	if(out != NULL) 
	{
		_total_item_size -= size ;
        
        	if(ends)
			--_total_item_count ;
	}

	return out ;
}

