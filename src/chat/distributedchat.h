/*******************************************************************************
 * libretroshare/src/chat: distributedchat.h                                   *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright 2014 by Cyril Soler <csoler@users.sourceforge.net>                *
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

#include <atomic>

#include <retroshare/rstypes.h>
#include <retroshare/rschats.h>
#include <retroshare/rsservicecontrol.h>

typedef RsPeerId ChatLobbyVirtualPeerId ;

struct RsItem;
class p3HistoryMgr ;
class p3IdService ;
class p3ServiceControl;
class RsChatLobbyItem ;
class RsChatLobbyListRequestItem ;
class RsChatLobbyListItem ;
class RsChatLobbyEventItem ;
class RsChatLobbyBouncingObject ;
class RsChatLobbyInviteItem_Deprecated ; // to be removed (deprecated since May 2017)
class RsChatLobbyInviteItem ;
class RsChatLobbyMsgItem ;
class RsChatLobbyConnectChallengeItem ;
class RsChatLobbyUnsubscribeItem ;

class RsChatItem ;
class RsChatMsgItem ;
class RsChatLobbyMsgItem ;
class RsChatLobbyEventItem ;
class RsChatLobbyBouncingObject ;
class RsGixs ;
class p3MobileLink ;
class p3MobilePush ;

class RsChatLobbyHistoryProbeItem ;
class RsChatLobbyHistoryProbeResponseItem ;
class RsChatLobbyHistoryRequestItem ;
class RsChatLobbyHistoryDataItem ;

class DistributedChatService
{
	public:
		DistributedChatService(uint32_t service_type,p3ServiceControl *sc,p3HistoryMgr *hm,RsGixs *is) ;

		virtual ~DistributedChatService() ;

		void flush() ;

		/// The service that tells which friends are phones in background,
		/// and whether this node is one (MobileLink). Set once at start-up.
		void setMobileLink(p3MobileLink *mobileLink) { mMobileLink = mobileLink ; }

		/// The service that turns the lines kept for a phone into push
		/// notifications (MobilePush). Set once at start-up.
		void setMobilePush(p3MobilePush *mobilePush) { mMobilePush = mobilePush ; }

		/// Phone side (MobileLink): count keep-alives for lobby lobby_id,
		/// signed now for later, the first one dated from and the next ones
		/// one keep-alive interval apart. The caller owns the items.
		bool makePresignedKeepAlives(const ChatLobbyId& lobby_id, rstime_t from, uint32_t count, std::list<RsChatLobbyEventItem*>& items) ;

		/// Home side (MobileLink): handles a keep-alive a phone signed in
		/// advance as if the phone had just sent it, so that it reaches the
		/// lobby's other participants. Takes ownership of item, whose peer
		/// id is the phone.
		void releasePresignedKeepAlive(RsChatLobbyEventItem *item) ;

		/// Home side: phone received the kept lines of batch (MobileLink).
		void heldLinesAcknowledged(const RsPeerId& phone, uint32_t batch) ;

		// Interface part to communicate with
		//
		bool getVirtualPeerId(const ChatLobbyId& lobby_id, RsPeerId& virtual_peer_id) ;
		void getChatLobbyList(std::list<ChatLobbyId>& clids) ;
		bool getChatLobbyInfo(const ChatLobbyId& id,ChatLobbyInfo& clinfo) ;
		bool acceptLobbyInvite(const ChatLobbyId& id,const RsGxsId& identity) ;
        bool denyLobbyInvite(const ChatLobbyId& id) ;
		void getPendingChatLobbyInvites(std::list<ChatLobbyInvite>& invites) ;
		void invitePeerToLobby(const ChatLobbyId&, const RsPeerId& peer_id,bool connexion_challenge = false) ;
		void unsubscribeChatLobby(const ChatLobbyId& lobby_id) ;
		bool setIdentityForChatLobby(const ChatLobbyId& lobby_id,const RsGxsId& nick) ;
		bool getIdentityForChatLobby(const ChatLobbyId& lobby_id,RsGxsId& nick) ;
		bool setDefaultIdentityForChatLobby(const RsGxsId& nick) ;
		void getDefaultIdentityForChatLobby(RsGxsId& nick) ;
		void setLobbyAutoSubscribe(const ChatLobbyId& lobby_id, const bool autoSubscribe);
		bool getLobbyAutoSubscribe(const ChatLobbyId& lobby_id);
		void sendLobbyStatusString(const ChatLobbyId& id,const std::string& status_string) ;
		void sendLobbyStatusPeerLeaving(const ChatLobbyId& lobby_id) ;

		ChatLobbyId createChatLobby(const std::string& lobby_name,const RsGxsId& lobby_identity,const std::string& lobby_topic, const std::set<RsPeerId>& invited_friends,ChatLobbyFlags flags) ;

		void getListOfNearbyChatLobbies(std::vector<VisibleChatLobbyRecord>& public_lobbies) ;

		/// Asks the friends for their lobbies now, whatever the last request:
		/// a phone back from the background has forgotten the lobbies it is
		/// not in (MobileLink).
		void requestLobbyListNow() ;
		bool joinVisibleChatLobby(const ChatLobbyId& id, const RsGxsId &gxs_id) ;

		// Lobby history retrieval protocol
		bool requestLobbyHistory(const ChatLobbyId& lobby_id, const std::set<RsPeerId>& peer_ids) ;
		bool requestLobbyHistoryFromPeer(const ChatLobbyId& lobby_id, const RsPeerId& peer_id, uint32_t max_count, uint32_t oldest_ts) ;
		void allowHistorySharing(bool allow) { _allow_history_sharing = allow; triggerConfigSave(); }
		bool isHistorySharingAllowed() const { return _allow_history_sharing; }

	protected:
		bool handleRecvItem(RsChatItem *) ;

		virtual void sendChatItem(RsChatItem *) =0 ;
		virtual void locked_storeIncomingMsg(RsChatMsgItem *) =0 ;
		virtual void triggerConfigSave() =0;

		void addToSaveList(std::list<RsItem*>& list) const ;
		bool processLoadListItem(const RsItem *item) ;

		void checkSizeAndSendLobbyMessage(RsChatItem *) ;

		bool sendLobbyChat(const ChatLobbyId &lobby_id, const std::string&) ;
		bool handleRecvChatLobbyMsgItem(RsChatMsgItem *item) ;

		bool checkSignature(RsChatLobbyBouncingObject *obj,const RsPeerId& peer_id) ;

	private:
		/// make some statistics about time shifts, to prevent various issues. 
		void addTimeShiftStatistics(int shift, const RsGxsId& gxsId) ;

		void handleRecvChatLobbyListRequest(RsChatLobbyListRequestItem *item) ;
		void handleRecvChatLobbyList(RsChatLobbyListItem *item) ;
		void handleRecvChatLobbyEventItem(RsChatLobbyEventItem *item) ;


		/// Checks that the lobby object is not flooding a lobby.
		bool locked_bouncingObjectCheck(RsChatLobbyBouncingObject *obj,const RsPeerId& peer_id,uint32_t lobby_count) ;

		/// receive and handle chat lobby item
		bool recvLobbyChat(RsChatLobbyMsgItem*,const RsPeerId& src_peer_id) ;
		void handleRecvLobbyInvite_Deprecated(RsChatLobbyInviteItem_Deprecated*) ; // to be removed (deprecated since May 2017)
		void handleRecvLobbyInvite(RsChatLobbyInviteItem*) ;
		void checkAndRedirectMsgToLobby(RsChatMsgItem*) ;
		void handleConnectionChallenge(RsChatLobbyConnectChallengeItem *item) ;
		void sendConnectionChallenge(ChatLobbyId id) ;
		void handleFriendUnsubscribeLobby(RsChatLobbyUnsubscribeItem*) ;
		void cleanLobbyCaches() ;
		bool bounceLobbyObject(RsChatLobbyBouncingObject *obj, const RsPeerId& peer_id) ;

		void sendLobbyStatusItem(const ChatLobbyId&, int type, const std::string& status_string) ;
		void sendLobbyStatusPeerChangedNickname(const ChatLobbyId& lobby_id, const std::string& newnick) ;

		void sendLobbyStatusNewPeer(const ChatLobbyId& lobby_id) ;
		void sendLobbyStatusKeepAlive(const ChatLobbyId&) ;

		// Lobby history retrieval handlers
		void handleRecvLobbyHistoryProbe(RsChatLobbyHistoryProbeItem *item) ;
		void handleRecvLobbyHistoryProbeResponse(RsChatLobbyHistoryProbeResponseItem *item) ;
		void handleRecvLobbyHistoryRequest(RsChatLobbyHistoryRequestItem *item) ;
		void handleRecvLobbyHistoryData(RsChatLobbyHistoryDataItem *item) ;

		bool locked_initLobbyBouncableObject(const ChatLobbyId& id,RsChatLobbyBouncingObject&) ;
		void locked_printDebugInfo() const ;
		RsGxsId locked_getDefaultIdentity();

		static ChatLobbyVirtualPeerId makeVirtualPeerId(ChatLobbyId) ;
		static uint64_t makeConnexionChallengeCode(const RsPeerId& peer_id,ChatLobbyId lobby_id,ChatLobbyMsgId msg_id) ;

		class ChatLobbyEntry: public ChatLobbyInfo
		{
			public:
				std::map<ChatLobbyMsgId,rstime_t> msg_cache ;
				RsPeerId virtual_peer_id ;
				int connexion_challenge_count ;
				rstime_t last_connexion_challenge_time ;
				bool joined_lobby_packet_sent;
				rstime_t last_keep_alive_packet_time ;
				std::set<RsPeerId> previously_known_peers ;
		};

		std::map<ChatLobbyId,ChatLobbyEntry> _chat_lobbys ;
		std::map<ChatLobbyId,ChatLobbyInvite> _lobby_invites_queue ;
		std::map<ChatLobbyId,VisibleChatLobbyRecord> _visible_lobbies ;
		std::map<ChatLobbyId,ChatLobbyFlags> _known_lobbies_flags ;	// flags for all lobbies, including the ones that are not known. So we can't
		std::map<ChatLobbyId,std::vector<RsChatLobbyMsgItem*> > _pendingPartialLobbyMessages ;	// store them in _chat_lobbies (subscribed lobbies) nor _visible_lobbies.
													// Known flags:
													// 		RS_CHAT_LOBBY_FLAGS_AUTO_SUBSCRIBE

		float _time_shift_average ;
		rstime_t last_lobby_challenge_time ; 					// prevents bruteforce attack
		rstime_t last_visible_lobby_info_request_time ;	// allows to ask for updates
		bool _should_reset_lobby_counts ;
		std::atomic<bool> _allow_history_sharing ;	// set from the GUI thread, read by the service

		// Lobby history retrieval: only DATA items answering a request we sent
		// to that peer for that lobby are accepted, within a deadline and up to
		// the number of messages we asked for and a total size.
		struct PendingLobbyHistoryRequest
		{
			rstime_t deadline ;
			uint32_t request_id ;	// data items of an earlier request to the same friend are refused
			uint32_t remaining_msgs ;
			uint32_t remaining_bytes ;
			uint32_t oldest_ts ;	// lines older than what we asked for are refused
		};
		std::map<std::pair<ChatLobbyId,RsPeerId>,PendingLobbyHistoryRequest> mPendingLobbyHistoryRequests ;

		bool isLobbyParticipatingFriend_locked(const ChatLobbyId& lobby_id, const RsPeerId& peer_id) const ;

		// Each probe reads the whole lobby history and each request sends up
		// to LOBBY_HISTORY_MAX_MSGS lines: a friend gets one answer of each
		// kind per lobby within LOBBY_HISTORY_MIN_SERVE_INTERVAL.
		std::map<std::pair<ChatLobbyId,RsPeerId>,rstime_t> mLastLobbyHistoryProbeServed ;
		std::map<std::pair<ChatLobbyId,RsPeerId>,rstime_t> mLastLobbyHistoryRequestServed ;
		bool locked_lobbyHistoryServeAllowed(std::map<std::pair<ChatLobbyId,RsPeerId>,rstime_t>& last_served, const ChatLobbyId& lobby_id, const RsPeerId& peer_id) ;
		RsGxsId _default_identity;
		std::map<ChatLobbyId,RsGxsId> _lobby_default_identity;

		uint32_t mServType ;
		RsMutex mDistributedChatMtx ;

		p3ServiceControl *mServControl; 
		p3HistoryMgr *mHistMgr;
		RsGixs *mGixs ;

		// What a home keeps for a phone in background (MobileLink), and sends
		// it when it comes back.

		struct HeldForPhone
		{
			/// Lobby lines, in arrival order.
			std::list<RsChatLobbyMsgItem*> lines ;

			/// The last keep-alive, join or leave of each participant, per
			/// lobby: enough for the phone's participant lists.
			std::map<std::pair<ChatLobbyId,RsGxsId>,RsChatLobbyEventItem*> presence ;

			/// The first sentLines lines were sent as batch sentBatch at
			/// sentAt and wait for the phone's acknowledgement; 0 when
			/// nothing is waiting.
			uint32_t sentBatch = 0 ;
			size_t sentLines = 0 ;
			rstime_t sentAt = 0 ;
		};

		/// Keeps item for phone, unless it is a line that mentions the phone,
		/// which goes at once. True when kept.
		bool locked_holdForQuietPhone(const RsPeerId& phone, RsChatLobbyBouncingObject *item, bool connected) ;

		/// Whether this node, a phone in background, leaves the lobby list
		/// alone (MobileLink). It does not when a lobby it subscribed to is
		/// still to be joined again, as after a start in background: then it
		/// asks, at most every ten minutes.
		bool skipLobbyListAsQuietPhone() ;
		rstime_t mLastQuietLobbyListRequest = 0 ;

		/// Whether line mentions phone's nickname in its lobby.
		bool locked_mentionsPhone(const RsPeerId& phone, const RsChatLobbyMsgItem& line) ;

		/// Sends their kept items to the phones that came back.
		void sendHeldItemsToReturnedPhones() ;

		p3MobileLink *mMobileLink = nullptr ;
		p3MobilePush *mMobilePush = nullptr ;
		std::map<RsPeerId,HeldForPhone> mHeldForPhones ;	// locked by mDistributedChatMtx
		uint32_t mLastHeldBatch = 0 ;						// locked by mDistributedChatMtx
};
