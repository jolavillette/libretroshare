/*******************************************************************************
 * libretroshare/src/pqi: pqiechoprobe.h                                       *
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
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "retroshare/rstypes.h"
#include "util/rsthreads.h"

//=============================================================================//
//                       Transport level echo / duplicate probe                //
//=============================================================================//
//
// Debugging facility. Every item sent to or received from a friend is
// fingerprinted (64 bits hash of its serialised form, i.e. what goes on the
// wire inside the SSL stream, all services). When a friend sends us an item
// that is byte for byte identical to one that, within the last minute,
//
//   - we SENT to some friend            -> ECHO
//   - we RECEIVED from another friend   -> DUP
//   - we RECEIVED from that same friend -> REPEAT
//
// it is counted per friend and per service, and a few samples are written out.
// This tells whether a friend sends back what we send (to it or to others),
// or relays copies of traffic it is not supposed to see, for any service, not
// only turtle.
//
// Off by default, driven by environment variables:
//
//   RS_ECHO_PROBE=1              enable (default: off)
//   RS_ECHO_PROBE_FILE=path      output file (default: ./echo-probe.log)
//   RS_ECHO_PROBE_WINDOW=secs    how long a fingerprint is remembered (def 60)
//
// Services whose items are identical by nature (heartbeat, status, bandwidth
// control, service info, RTT, slicing probe) and items of 16 bytes or less are
// ignored: they would match all the time without meaning anything.
//
// Output: one summary block per minute (friends with at least one ECHO, DUP or
// REPEAT, broken down by service) and at most a few sample lines per friend,
// service and kind. Peer ids only: names are resolved by the turtle journal
// (PEER lines) or the GUI. Nothing here calls out of the probe while a
// streamer is locked.
//
class PqiEchoProbe
{
	public:
		static PqiEchoProbe& instance();

		bool enabled() const { return mEnabled ; }

		/// Called by pqistreamer with the serialised item, from its own threads.
		void sent    (const RsPeerId& to,  const void *data,uint32_t size) ;
		void received(const RsPeerId& from,const void *data,uint32_t size) ;

	private:
		PqiEchoProbe() ;

		enum Kind : uint8_t { ECHO = 0, DUP = 1, REPEAT = 2 } ;

		class Seen
		{
			public:
				Seen() : sent_ms(0),recv_ms(0),sent_to(0),recv_from(0) {}

				uint64_t sent_ms ;    // first time we sent it, 0 if never
				uint64_t recv_ms ;    // first time we received it, 0 if never
				uint16_t sent_to ;    // peer index
				uint16_t recv_from ;  // peer index
		};

		class PeerStat
		{
			public:
				PeerStat() : in(0),out(0) {}

				uint64_t in,out ;
				std::map<uint16_t,uint32_t> count[3] ;   // per kind, per service
				std::map<uint32_t,uint32_t> samples ;    // (kind<<16|service) -> samples written this lapse
		};

		void record(bool outgoing,const RsPeerId& peer,const void *data,uint32_t size) ;
		uint16_t peerIdx(const RsPeerId& p) ;      // mMtx must be locked
		void expire(uint64_t now) ;                // mMtx must be locked
		std::string summary(uint64_t now) ;        // mMtx must be locked

		static uint64_t hash(const uint8_t *d,uint32_t size) ;
		static bool ignoredService(uint16_t service) ;
		static std::string serviceName(uint16_t service) ;

		RsMutex mMtx ;

		bool        mEnabled ;
		std::string mFileName ;
		uint64_t    mWindowMs ;

		std::unordered_map<uint64_t,Seen>        mSeen ;
		std::deque<std::pair<uint64_t,uint64_t> > mOrder ;   // (first seen ms, fp), oldest first

		std::map<RsPeerId,uint16_t> mPeerIdx ;
		std::vector<RsPeerId>       mPeers ;                  // index 0 unused

		std::map<uint16_t,PeerStat> mStats ;
		std::vector<std::string>    mPending ;                // sample lines not written yet
		uint64_t                    mLastFlushMs ;
		uint32_t                    mSamplesThisLapse ;
};
