/*******************************************************************************
 * libretroshare/src/pqi: pqiqosstreamer.h                                     *
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
#pragma once

#include "pqiqos.h"
#include "pqithreadstreamer.h"

class pqiQoSstreamer: public pqithreadstreamer, public pqiQoS
{
	public:
		pqiQoSstreamer(PQInterface *parent, RsSerialiser *rss, const RsPeerId& peerid, BinInterface *bio_in, int bio_flagsin);

		static const uint32_t PQI_QOS_STREAMER_MAX_LEVELS =  10 ;
        static const float    PQI_QOS_STREAMER_ALPHA ;

		virtual void locked_storeInOutputQueue(void *ptr, int size, int priority) ;
		virtual int locked_out_queue_size() const { return _total_item_count ; }
		virtual void locked_clear_out_queue() ;
		virtual int locked_compute_out_pkt_size() const { return _total_item_size ; }
		virtual  void *locked_pop_out_data(uint32_t max_slice_size,uint32_t& size,bool& starts,bool& ends,uint32_t& packet_id);
                //virtual int  locked_gatherStatistics(std::vector<uint32_t>& per_service_count,std::vector<uint32_t>& per_priority_count) const; // extracting data.


		virtual int getQueueSize(bool in) ;

	protected:
		virtual void locked_tickOutQueue(float out_rate_kBps) ;

	private:
		uint32_t _total_item_size ;
		uint32_t _total_item_count ;

		// Congestion: while the friend needs too long to drain our queue, only items of
		// priority PQI_QOS_CONGESTION_MIN_PRIORITY and above are queued (see pqiqosstreamer.cc).
		void locked_updateCongestion(float out_rate_kBps) ;
		void locked_reportCongestion(rstime_t now) ;
		bool     _congested ;
		rstime_t _congested_since ;
		rstime_t _last_congestion_end ;
		rstime_t _congestion_hold ;
		rstime_t _last_congestion_check ;
		uint32_t _seconds_above ;
		uint32_t _seconds_below ;
		float    _last_drain ;
		rstime_t _last_congestion_report ;
		std::vector<uint32_t> _refused_per_priority ;
		uint32_t _refused_bytes ;
		uint32_t _purged ;

		// Turtle tunnel requests/results that waited too long in the queue are dropped
		// instead of being sent late (see locked_removeStaleTunnelItems()).
		void locked_removeStaleTunnelItems() ;
		rstime_t _last_stale_check ;
		rstime_t _last_stale_report ;
		uint32_t _stale_dropped ;
		uint32_t _stale_dropped_bytes ;
		rstime_t _stale_max_age ;
};

