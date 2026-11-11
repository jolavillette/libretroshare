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
#include <unordered_map>
#include <deque>
#include <set>
#include <string>
#include <vector>

#include "turtle/turtletypes.h"

class RsTurtleGenericTunnelItem ;
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
// When the recorder is on, it also keeps, to explain where a duplicate tunnel
// result comes from:
//   - per tunnel request: the peers it was forwarded to, and every bounce
//     (sender, depth, delay), so a dump tells whether we are the origin of the
//     peer that later sends the duplicate result;
//   - per tunnel: a fingerprint (64 bits hash of the serialised item) of the
//     last items routed, so a dump tells whether the items of the offending
//     peer are copies of items seen on the real route, and with which delay.
//     For 5 minutes after the first mismatch every item of that tunnel is
//     written to the dump file;
//   - for 30 minutes after the last dropped item, one FOLLOW line per minute
//     per broken tunnel: items accepted from each end, items dropped per
//     sender, whether our own entry has expired;
//   - the name and announced RetroShare version of every peer involved;
//   - for every "suspect" peer (one that sent us a dropped item or a duplicate
//     result in the last 30 minutes), one PEERSTATE line per minute: online or
//     not (and the transitions), last RTT and clock offset measured by the RTT
//     service, and its turtle activity with us in that minute: results it
//     sent, duplicates, tunnels created through it, items accepted from it
//     and items dropped from it.
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
			T_CLOSE          = 16,	// tunnel entry removed
			OK_FROM_ORIGIN   = 17	// tunnel result sent by the friend the request came from
		};

		static TurtleJournal& instance();

		bool enabled()         const { return mEnabled ; }
		bool guardEnabled()    const { return mGuard ; }
		bool verboseRouting()  const { return mVerboseRouting ; }

		//--------------------------- Tunnel requests ---------------------------//

		void trIn      (TurtleTunnelRequestId rid,const TurtlePeerId& from,uint16_t depth,const TurtleFileHash& hash,uint32_t partial_in);
		void trBounce  (TurtleTunnelRequestId rid,const TurtlePeerId& from,const TurtlePeerId& known_origin,uint32_t age,uint16_t depth);
		void trFwdTo   (TurtleTunnelRequestId rid,const TurtlePeerId& to);
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

		/// What a relay can tell about a tunnel item without decrypting it: the
		/// fingerprint, the serialised size and, for generic data items, the clear
		/// prefix of their payload. Encrypted file transfer payloads start with
		/// 0xae 0xad, a format byte, a 12 bytes IV and the clear size of the inner
		/// file transfer item (ftserver.cc encryptItem), which tells its kind.
		class ItemDesc
		{
			public:
				ItemDesc() : fp(0),size(0),inner(0),payload(PAYLOAD_NONE) {}

				enum : uint8_t { PAYLOAD_NONE = 0, PAYLOAD_ENCRYPTED_FT = 1, PAYLOAD_CLEAR_ITEM = 2, PAYLOAD_OPAQUE = 3 } ;

				uint64_t fp ;
				uint32_t size ;     // serialised turtle item, header included
				uint32_t inner ;    // encrypted ft: inner item size; clear item: service<<8|subtype; opaque: first 4 bytes
				uint8_t  payload ;
		};
		static std::string payloadStr(const ItemDesc& d) ;

		void itemMismatch     (TurtleTunnelId tid,const TurtlePeerId& from,const TurtlePeerId& src,const TurtlePeerId& dst,
		                       uint8_t item_subtype,uint32_t tunnel_age,const ItemDesc& d);

		/// An item accepted on a tunnel: from one end to the other, or to/from us.
		/// A null `from` means we emitted it, a null `to` means it is for us.
		void itemRouted       (TurtleTunnelId tid,const TurtlePeerId& from,const TurtlePeerId& to,
		                       uint8_t item_subtype,const ItemDesc& d);

		/// 64 bits FNV-1a hash of the serialised item (identical for copies of the
		/// same item, whoever relays them), its size and payload prefix. Only
		/// computed when the recorder is on.
		static ItemDesc fingerprint(RsTurtleGenericTunnelItem *item) ;
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

		class ItemSeen
		{
			public:
				uint64_t ms ;
				uint64_t fp ;
				ItemDesc d ;
				uint16_t from ;     // peer index, 0 = us
				uint16_t to ;       // peer index, 0 = us
				uint8_t  subtype ;
				uint8_t  accepted ;
		};

		class TunnelRecord
		{
			public:
				TunnelRecord() : first_ms(0),last_ms(0),mismatch_count(0),announced_after_mismatch(false),dumped(false),
				                 capture_until_ms(0),captured(0),watched(false),last_reject_ms(0),closed_ms(0),
				                 f_from_src(0),f_from_dst(0),f_local(0) {}

				uint64_t           first_ms ;
				uint64_t           last_ms ;
				TurtleFileHash     hash ;                     // hash of the request that created the id, if known
				uint32_t           mismatch_count ;
				bool               announced_after_mismatch ; // a result was forwarded upstream while the endpoints differed
				bool               dumped ;
				std::vector<Event> events ;

				std::vector<ItemSeen> ring ;                  // last routed items, oldest first
				uint64_t           capture_until_ms ;         // every item is written out until then
				uint32_t           captured ;

				bool               watched ;                  // FOLLOW lines are printed for this tunnel
				uint64_t           last_reject_ms ;
				uint64_t           closed_ms ;                // our own entry expired at that time, 0 if alive
				TurtlePeerId       src,dst ;                  // our endpoints when the first mismatch hit
				uint32_t           f_from_src,f_from_dst,f_local ;  // FOLLOW counters for the current minute
				std::map<uint16_t,uint32_t> f_rejected ;
		};

		class Bounce
		{
			public:
				uint32_t dms ;      // ms after the request was first received
				uint16_t peer ;
				uint16_t depth ;
		};

		// Every request id accepted as new in the last hour, to see a request come
		// back after the router forgot it (TUNNEL_REQUESTS_LIFE_TIME): the router
		// then takes it for a new request, with whoever brought it back as origin.
		class RidSeen
		{
			public:
				uint64_t first_ms ;
				uint64_t last_ms ;
				uint32_t hash4 ;      // first 4 bytes of the file hash: tells a reborn request from a collision
				uint16_t first_from ; // peer index
				uint16_t times ;
		};

		class RequestRecord
		{
			public:
				RequestRecord() : ms(0),partial_in(0),partial_out(0),depth(0),n_fwd(0),bounces_dropped(0) {}

				uint64_t       ms ;
				TurtlePeerId   origin ;
				TurtleFileHash hash ;
				uint32_t       partial_in ;
				uint32_t       partial_out ;
				uint16_t       depth ;
				uint16_t       n_fwd ;
				std::vector<uint16_t> fwd_to ;   // peers this request was forwarded to (indices)
				std::vector<Bounce>   bounces ;  // later copies of this request, capped
				uint32_t       bounces_dropped ;
		};

		void push(TurtleTunnelId tid,uint8_t kind,uint32_t rid,uint32_t aux,
		          const TurtlePeerId& p1,const TurtlePeerId& p2);	// mJournalMtx must be locked
		void dumpTunnel(TurtleTunnelId tid);                        // mJournalMtx must be locked
		void sweep(uint64_t now_ms);                                // mJournalMtx must be locked
		std::string formatEvent(TurtleTunnelId tid,const Event& e) const;

		uint16_t peerIdx(const TurtlePeerId& p);                    // mJournalMtx must be locked; 0 for a null id
		std::string peerStr(uint16_t idx) const;                    // mJournalMtx must be locked
		void recordItem(TurtleTunnelId tid,TunnelRecord& rec,uint64_t now,uint16_t from,uint16_t to,
		                uint8_t subtype,const ItemDesc& d,bool accepted);  // mJournalMtx must be locked
		std::string copyOf(const TunnelRecord& rec,uint64_t fp,uint16_t from,uint64_t ms) const;
		void followLines(uint64_t now_ms,std::ostringstream& o);    // mJournalMtx must be locked

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

		std::unordered_map<uint32_t,RidSeen>          mRidHistory ;
		std::deque<std::pair<uint64_t,uint32_t> >     mRidOrder ;     // (first ms, rid), oldest first
		uint32_t mRebornLinesThisLapse ;
		uint32_t mSelfLoopLinesThisLapse ;
		uint64_t                 mLastSummaryMs ;

		class PeerTurtleStat
		{
			public:
				PeerTurtleStat() : ok_in(0),ok_twice(0),t_via(0),acc_from(0),drop_from(0),
				                   bounces(0),slow_bounces(0),max_bounce_ms(0),ok_late(0) {}

				uint32_t ok_in,ok_twice,t_via,acc_from,drop_from ;
				uint32_t bounces,slow_bounces,max_bounce_ms,ok_late ;   // how late this friend delivers requests / results
		};

		std::map<uint16_t,PeerTurtleStat> mPeerStats ;   // current minute, all peers
		std::map<uint16_t,uint64_t>       mSuspects ;    // peer index -> last dropped item / duplicate result (ms)
		std::map<TurtlePeerId,int>        mLastOnline ;  // only touched from tick(): -1 unknown, 0 offline, 1 online

		std::map<TurtlePeerId,uint16_t> mPeerIdx ;
		std::vector<TurtlePeerId>       mPeers ;          // index 0 = null id (us)
		std::set<TurtlePeerId>          mPendingPeerInfo ;// peers to name in the dump file
		std::set<TurtlePeerId>          mPeerInfoDone ;

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
					tr_reborn = tr_rid_collision = ok_from_origin = 0 ;
					mirror_here = self_tunnel = 0 ;
					ok_in = ok_no_request = ok_twice = ok_late = 0 ;
					t_create = t_overwrite = t_found_match = t_found_mismatch = t_close = 0 ;
					ok_fwd_after_mismatch = ok_held = 0 ;
					item_mismatch = item_unknown_tid = 0 ;
					mismatch_peers.clear() ;
					mismatch_tunnels.clear() ;
					mismatch_tunnels_announced = 0 ;
					mismatch_payloads.clear() ;
				}

				uint64_t tr_in,tr_bounce,tr_fwd,tr_answered ;
				uint64_t tr_reborn,tr_rid_collision,ok_from_origin ;
				uint64_t mirror_here,self_tunnel ;   // we bounced an item back to its sender / stored a tunnel with one friend at both ends
				uint64_t ok_in,ok_no_request,ok_twice,ok_late ;
				uint64_t t_create,t_overwrite,t_found_match,t_found_mismatch,t_close ;
				uint64_t ok_fwd_after_mismatch,ok_held ;
				uint64_t item_mismatch,item_unknown_tid ;

				std::map<TurtlePeerId,uint64_t> mismatch_peers ;   // who sends the dropped items
				std::map<TurtleTunnelId,uint64_t> mismatch_tunnels ;// which tunnel ids are hit
				uint64_t mismatch_tunnels_announced ;              // ...among which, how many we announced upstream
				std::map<std::string,uint64_t> mismatch_payloads ; // what the dropped items carry (recorder on only)
		};

		Counters mCounters ;
};
