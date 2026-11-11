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
// Burst follow-up: when a turtle tunnel item (tunnel ok, data, file transfer
// items) comes back as an ECHO, i.e. a friend B sends us an item we had sent to
// another friend U, the probe takes every item we sent to U within one second of
// that one (the burst), watches for two minutes which of them come back, from
// whom and in which order, then writes a BURST block. That tells whether a whole
// block of our stream to U is replayed (transport) or only some tunnel items
// come back (turtle routing). At most 10 bursts are opened per minute (3 for
// file maps and chunk maps, which echo routinely).
//
// Multi-send check: a turtle tunnel item (tunnel ok, data, file transfer items)
// goes to exactly one friend, the next hop of its tunnel. When the same bytes
// are serialised for a second friend, a MULTISEND line is written (and the
// first ones of each minute go to stderr): that would be our own node sending
// a copy of a tunnel item to a friend that is not on the tunnel.
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

		/// Called by pqiQoSstreamer when a whole item leaves the output queue to be
		/// written: measures how long it waited in our own QoS queue.
		void dequeued(const RsPeerId& to,const void *data) ;

	private:
		PqiEchoProbe() ;

		enum Kind : uint8_t { ECHO = 0, DUP = 1, REPEAT = 2 } ;

		class Seen
		{
			public:
				Seen() : sent_ms(0),recv_ms(0),sent_to(0),recv_from(0),sent_to2(0),n_sent_peers(0) {}

				uint64_t sent_ms ;    // first time we sent it, 0 if never
				uint64_t recv_ms ;    // first time we received it, 0 if never
				uint16_t sent_to ;    // peer index
				uint16_t recv_from ;  // peer index
				uint16_t sent_to2 ;   // a second friend we sent the same bytes to, 0 if none
				uint8_t  n_sent_peers ;
		};

		class PeerStat
		{
			public:
				PeerStat() : in(0),out(0) {}

				uint64_t in,out ;
				std::map<uint16_t,uint32_t> count[3] ;   // per kind, per service
				std::map<uint32_t,uint32_t> samples ;    // (kind<<16|service) -> samples written this lapse
		};

		class SentRec
		{
			public:
				uint64_t ms ;
				uint64_t fp ;
				uint64_t seq ;        // rank in our outgoing stream to that friend
				uint32_t size ;
				uint32_t tunnel_id ;  // turtle tunnel items only, else 0
				uint32_t ft_inner ;   // encrypted file transfer payload: clear size of the inner ft item, else 0
				uint16_t service ;
				uint8_t  subtype ;
		};

		class WatchItem
		{
			public:
				WatchItem() : back_ms(0),back_seq(0),back_from(0),back_count(0) {}

				SentRec  s ;
				uint64_t back_ms ;    // first time it came back, 0 if never
				uint64_t back_seq ;   // rank in the incoming stream of the friend that sent it back
				uint16_t back_from ;
				uint16_t back_count ;
		};

		class Watch
		{
			public:
				uint32_t id ;
				uint16_t to ;             // the friend U we sent the burst to
				uint16_t trigger_from ;   // the friend B that echoed the trigger item
				uint64_t t0 ;             // when we sent the trigger item to U
				uint64_t trigger_ms ;     // when B sent it back
				uint64_t trigger_fp ;
				uint16_t trigger_service ;
				uint8_t  trigger_subtype ;
				uint16_t trigger_also_sent_to ;   // the trigger item was ALSO serialised for this friend, 0 if not
				std::vector<WatchItem> items ;
		};

		// Output queue delay: serialised item pointer -> when it was queued.
		class Queued
		{
			public:
				uint64_t ms ;
				uint64_t fp ;         // to make sure the pointer still holds the same item when it leaves
				uint32_t size ;
				uint16_t peer ;
				uint16_t service ;
				uint8_t  subtype ;
		};
		class QDelayStat
		{
			public:
				QDelayStat() : n(0),sum_ms(0),max_ms(0),over5(0),over20(0) {}
				uint32_t n ;
				uint64_t sum_ms ;
				uint32_t max_ms ;
				uint32_t over5,over20 ;
		};
		// Link stall / resume on the receiving side: a friend silent for more than
		// RESUME_GAP_MS, then a burst.
		class Resume
		{
			public:
				Resume() : start_ms(0),gap_ms(0),n(0),n_tr(0),n_ok(0),n_data(0),n_other_turtle(0) {}
				uint64_t start_ms,gap_ms ;
				uint32_t n,n_tr,n_ok,n_data,n_other_turtle ;
		};
		void noteReceived(uint16_t idx,uint64_t now,uint16_t service,uint8_t subtype) ;	// mMtx must be locked

		static int delayClass(uint16_t service,uint8_t subtype) ;
		static const char *delayClassName(int c) ;

		void record(bool outgoing,const RsPeerId& peer,const void *data,uint32_t size) ;
		uint16_t peerIdx(const RsPeerId& p) ;      // mMtx must be locked
		void expire(uint64_t now) ;                // mMtx must be locked
		std::string summary(uint64_t now) ;        // mMtx must be locked
		void openWatch(uint16_t to,uint16_t from,uint64_t t0,uint64_t now,uint64_t fp,uint16_t service,uint8_t subtype) ;	// mMtx locked
		void closeWatches(uint64_t now,bool all) ;                     // mMtx must be locked
		std::string watchReport(const Watch& w) ;                      // mMtx must be locked
		static bool isTunnelItem(uint16_t service,uint8_t subtype) ;
		static std::string subtypeName(uint16_t service,uint8_t subtype) ;

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

		std::map<uint16_t,std::deque<SentRec> > mSentLog ;   // per friend, last window
		std::map<uint16_t,uint64_t>             mSendSeq ;
		std::map<uint16_t,uint64_t>             mRecvSeq ;
		std::map<uint32_t,Watch>                mWatches ;
		std::unordered_multimap<uint64_t,std::pair<uint32_t,uint32_t> > mWatchFp ;   // fp -> (watch, item)
		uint32_t mNextWatchId ;
		uint32_t mWatchesThisLapse ;
		uint32_t mMinorWatchesThisLapse ;
		uint32_t mMultiSendThisLapse ;     // turtle tunnel items serialised for two different friends
		uint32_t mMultiSendLinesThisLapse ;

		std::unordered_map<const void*,Queued>         mQueued ;
		std::map<std::pair<uint16_t,int>,QDelayStat>  mQDelay ;    // (peer, class), current minute
		uint32_t mQWaitLinesThisLapse ;
		std::map<uint16_t,uint64_t> mLastRx ;     // per friend, last item received (any service)
		std::map<uint16_t,Resume>   mResumes ;    // bursts being counted
		uint32_t mQStale ;          // dequeued pointer whose bytes no longer match: not counted
		uint32_t mQMatched ;
};
