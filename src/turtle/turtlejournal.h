/*******************************************************************************
 * libretroshare/src/turtle: turtlejournal.h                                   *
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
#include <map>
#include <string>
#include <vector>

#include "turtle/turtletypes.h"
#include "util/rsthreads.h"

//=============================================================================//
//                     Turtle tunnel id black box recorder                     //
//=============================================================================//
//
// Debugging facility for the "item mismatches tunnel src/dst ids" condition.
//
// The turtle router routes items using a single 32 bits tunnel id which is
// computed by the tunnel responder and kept identical along the whole route.
// When an item arrives on a tunnel id that is known locally but with different
// endpoints, the item is dropped. The error message alone does not tell where
// the offending tunnel id comes from, so this class records the full lifecycle
// of every tunnel id and, on the first mismatch for a given id, dumps its
// complete history: which tunnel request created it, which tunnel result
// confirmed it, to which peer the result was forwarded, when it was closed, and
// which item finally hit the mismatch.
//
// Everything is off by default and controlled by environment variables:
//
//   RS_TURTLE_JOURNAL=1          enable the recorder (default: off)
//   RS_TURTLE_JOURNAL_FILE=path  where to dump (default: ./turtle-journal.log)
//   RS_TURTLE_JOURNAL_IDS=n      max tunnel ids kept in memory (default 100000)
//   RS_TURTLE_JOURNAL_TTL=secs   how long an untouched record is kept (def 900)
//   RS_TURTLE_GUARD=1            do not forward a tunnel result upstream when
//                                the tunnel id is already known with different
//                                endpoints (candidate fix, default: off)
//   RS_TURTLE_VERBOSE_ROUTING=1  restore the historical one-block-per-dropped
//                                item logging (default: off, aggregated)
//
// PRIVACY NOTE: a transit node deliberately does not keep the file hash of the
// tunnels it relays (p3turtle.cc clears TurtleTunnel::hash for transit
// tunnels). When enabled, this recorder keeps the hash and the route of the
// tunnel requests it sees, in memory and in its dump file. This is meant for
// debugging on one's own node, must stay disabled by default, and the dump file
// must not be shared as is.
//
class TurtleJournal
{
	public:
		enum Kind : uint8_t
		{
			TR_IN            =  0,	// tunnel request received
			TR_BOUNCE        =  1,	// tunnel request dropped: already known
			TR_FWD           =  2,	// tunnel request forwarded to n peers
			TR_ANSWERED      =  3,	// we host the hash: tunnel ends here
			OK_IN            =  4,	// tunnel result received
			OK_NO_REQUEST    =  5,	// tunnel result dropped: unknown request
			OK_TWICE         =  6,	// tunnel result dropped: already answered
			OK_LATE          =  7,	// tunnel result dropped: request too old
			T_CREATE         =  8,	// transit tunnel entry created
			T_OVERWRITE      =  9,	// tunnel entry overwritten by an ending tunnel
			T_FOUND_MATCH    = 10,	// result for a known id, same endpoints
			T_FOUND_MISMATCH = 11,	// result for a known id, different endpoints
			OK_FWD           = 12,	// tunnel result forwarded upstream
			OK_HELD          = 13,	// tunnel result NOT forwarded (guard)
			ITEM_MISMATCH    = 14,	// item dropped: sender is not an endpoint
			ITEM_UNKNOWN_TID = 15,	// item dropped: unknown tunnel id
			T_CLOSE          = 16	// tunnel entry removed
		};

		static TurtleJournal& instance();

		bool enabled()         const { return mEnabled ; }
		bool guardEnabled()    const { return mGuard ; }
		bool verboseRouting()  const { return mVerboseRouting ; }

		//--------------------------- Tunnel requests ---------------------------//

		void trIn      (TurtleTunnelRequestId rid,const TurtlePeerId& from,uint16_t depth,const TurtleFileHash& hash,uint32_t partial_in);
		void trBounce  (TurtleTunnelRequestId rid,const TurtlePeerId& from,const TurtlePeerId& known_origin,uint32_t age);
		void trFwd     (TurtleTunnelRequestId rid,uint32_t partial_out,uint16_t n_peers);
		void trAnswered(TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& to,const TurtleFileHash& hash,
		                bool overwrote,const TurtlePeerId& old_src,const TurtlePeerId& old_dst);

		//--------------------------- Tunnel results ----------------------------//

		void okIn         (TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& from);
		void okNoRequest  (TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& from);
		void okTwice      (TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& from);
		void okLate       (TurtleTunnelRequestId rid,TurtleTunnelId tid,const TurtlePeerId& from,uint32_t age);
		void tunnelCreated(TurtleTunnelId tid,TurtleTunnelRequestId rid,const TurtlePeerId& src,const TurtlePeerId& dst);
		void tunnelFound  (TurtleTunnelId tid,TurtleTunnelRequestId rid,
		                   const TurtlePeerId& stored_src,const TurtlePeerId& stored_dst,
		                   const TurtlePeerId& new_src,const TurtlePeerId& new_dst,bool mismatch);
		void okForwarded  (TurtleTunnelId tid,TurtleTunnelRequestId rid,const TurtlePeerId& to,bool after_mismatch);
		void okHeld       (TurtleTunnelId tid,TurtleTunnelRequestId rid,const TurtlePeerId& to);

		//------------------------------- Routing -------------------------------//

		void itemMismatch     (TurtleTunnelId tid,const TurtlePeerId& from,const TurtlePeerId& src,const TurtlePeerId& dst,
		                       uint8_t item_subtype,uint32_t tunnel_age);
		void itemUnknownTunnel(TurtleTunnelId tid,const TurtlePeerId& from,uint8_t item_subtype);
		void tunnelClosed     (TurtleTunnelId tid,const TurtlePeerId& src,const TurtlePeerId& dst,uint32_t age);

		//------------------------------ Periodic -------------------------------//

		/// Called from p3turtle::tick(), off turtle mutex: writes pending dumps
		/// and prints the aggregated summary every 60 seconds.
		void tick(uint32_t live_tunnels,uint32_t live_requests);

	private:
		TurtleJournal();

		class Event
		{
			public:
				uint64_t     ms ;      // wall clock, milliseconds since epoch
				uint32_t     rid ;     // related tunnel request id, 0 if none
				uint32_t     aux ;     // depth / peer count / age / item subtype
				uint8_t      kind ;
				TurtlePeerId p1 ;
				TurtlePeerId p2 ;
		};

		class TunnelRecord
		{
			public:
				TunnelRecord() : first_ms(0),last_ms(0),mismatch_count(0),announced_after_mismatch(false),dumped(false) {}

				uint64_t           first_ms ;
				uint64_t           last_ms ;
				TurtleFileHash     hash ;                     // hash of the request that created the id, if known
				uint32_t           mismatch_count ;
				bool               announced_after_mismatch ; // a result was forwarded upstream while the endpoints differed
				bool               dumped ;
				std::vector<Event> events ;
		};

		class RequestRecord
		{
			public:
				RequestRecord() : ms(0),partial_in(0),partial_out(0),depth(0),n_fwd(0) {}

				uint64_t       ms ;
				TurtlePeerId   origin ;
				TurtleFileHash hash ;
				uint32_t       partial_in ;
				uint32_t       partial_out ;
				uint16_t       depth ;
				uint16_t       n_fwd ;
		};

		void push(TurtleTunnelId tid,uint8_t kind,uint32_t rid,uint32_t aux,
		          const TurtlePeerId& p1,const TurtlePeerId& p2);	// mJournalMtx must be locked
		void dumpTunnel(TurtleTunnelId tid);                        // mJournalMtx must be locked
		void sweep(uint64_t now_ms);                                // mJournalMtx must be locked
		std::string formatEvent(TurtleTunnelId tid,const Event& e) const;

		mutable RsMutex mJournalMtx ;

		bool        mEnabled ;
		bool        mGuard ;
		bool        mVerboseRouting ;
		std::string mFileName ;
		uint32_t    mMaxIds ;
		uint32_t    mTtl ;

		std::map<TurtleTunnelId,TunnelRecord>        mTunnels ;
		std::map<TurtleTunnelRequestId,RequestRecord> mRequests ;

		std::vector<std::string> mPendingDumps ;
		uint64_t                 mLastSummaryMs ;

		//------------------------------ Counters -------------------------------//
		// Always maintained, even when the recorder is disabled: they feed the
		// throttled replacement of the historical per-item error messages.

		class Counters
		{
			public:
				Counters() { clear() ; }
				void clear()
				{
					tr_in = tr_bounce = tr_fwd = tr_answered = 0 ;
					ok_in = ok_no_request = ok_twice = ok_late = 0 ;
					t_create = t_overwrite = t_found_match = t_found_mismatch = t_close = 0 ;
					ok_fwd_after_mismatch = ok_held = 0 ;
					item_mismatch = item_unknown_tid = 0 ;
					mismatch_peers.clear() ;
					mismatch_tunnels.clear() ;
					mismatch_tunnels_announced = 0 ;
				}

				uint64_t tr_in,tr_bounce,tr_fwd,tr_answered ;
				uint64_t ok_in,ok_no_request,ok_twice,ok_late ;
				uint64_t t_create,t_overwrite,t_found_match,t_found_mismatch,t_close ;
				uint64_t ok_fwd_after_mismatch,ok_held ;
				uint64_t item_mismatch,item_unknown_tid ;

				std::map<TurtlePeerId,uint64_t> mismatch_peers ;   // who sends the dropped items
				std::map<TurtleTunnelId,uint64_t> mismatch_tunnels ;// which tunnel ids are hit
				uint64_t mismatch_tunnels_announced ;              // ...among which, how many we announced upstream
		};

		Counters mCounters ;
};
