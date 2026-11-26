/*******************************************************************************
 * libretroshare/src/services: p3mobilelink.h                                  *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright (C) 2026  RetroShare Team <contact@retroshare.cc>                 *
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
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <mutex>
#include <set>
#include <vector>

#include "pqi/p3cfgmgr.h"
#include "pqi/pqiservicemonitor.h"
#include "retroshare/rsmobilelink.h"
#include "rsitems/rsmobilelinkitems.h"
#include "services/p3service.h"
#include "turtle/turtletypes.h"
#include "util/rstime.h"

class p3ServiceControl;
class DistributedChatService;

/**
 * The MobileLink service, in both its roles.
 *
 * On a phone (setPhoneMode(true)) it tells each connected friend that runs
 * MobileLink the phone's identities (HELLO) and its state (STATE: quiet or
 * not), and sends the keep-alives the app asks for (PING).
 *
 * On a home, any node that serves phones (on by default), it records the
 * phones among its friends and answers the other services' questions: the
 * turtle router asks it which tunnel and search requests to pass on to a
 * friend. A home never gets a phone's keys, only its public identity ids.
 */
class p3MobileLink: public RsMobileLink, public p3FastService,
        public p3Config, public pqiServiceMonitor
{
public:
	explicit p3MobileLink(p3ServiceControl* serviceControl);

	RsServiceInfo getServiceInfo() override;

	// RsMobileLink
	void setPhoneMode(bool phone) override;
	bool getPhoneMode() override;
	void setQuiet(bool quiet) override;
	bool getQuiet() override;
	void setKeepAliveInterval(uint32_t seconds) override;
	uint32_t getKeepAliveInterval() override;
	bool keepAliveNow(uint32_t timeoutSeconds) override;
	void getHomes(std::vector<RsMobileLinkHomeInfo>& homes) override;
	void setServePhones(bool serve) override;
	bool getServePhones() override;
	void getPhones(std::vector<RsMobileLinkPhoneInfo>& phones) override;

	/// Home side: whether to pass a tunnel request on to friend peer. False
	/// only for a phone, when the request is for none of its identities.
	bool wantsTunnelRequest(const RsPeerId& peer, const TurtleFileHash& hash);

	/// Home side: whether to pass a search request on to friend peer. False
	/// for a phone.
	bool wantsSearchRequest(const RsPeerId& peer);

	/// Home side: whether friend peer is a phone in background.
	bool isQuietPhone(const RsPeerId& peer);

	/// Phone side: whether this node is a phone in background.
	bool localQuiet();

	/// Home side: whether phone acknowledges the lobby lines kept for it.
	/// The home then keeps them until the acknowledgement comes.
	bool acknowledgesHeld(const RsPeerId& phone);

	/// Home side: tells phone that the kept lines of batch are all sent.
	/// To call right after sending them.
	void sendHeldEnd(const RsPeerId& phone, uint32_t batch);

	/// How long the connection to peer may stay silent before it is taken
	/// for dead, in seconds; 0 for the usual timeouts. A phone in background
	/// and its home send each other only the phone's keep-alive and its
	/// answer, so they need much longer than the heartbeat's timeouts.
	rstime_t silenceTolerance(const RsPeerId& peer);

	/// Whether to send peer the periodic heartbeat. Not between a phone in
	/// background and its home: the phone's keep-alive replaces it.
	bool wantsHeartbeat(const RsPeerId& peer);

	/// Whether the link to peer is between a phone in background and its
	/// home: the periodic services (heartbeat, RTT, bandwidth control,
	/// ban list, reputation) send nothing on it.
	bool isQuietLink(const RsPeerId& peer);

	/// Home side: the identity phone uses in chat lobby lobby, as its HELLO
	/// said. False when unknown.
	bool phoneLobbyIdentity( const RsPeerId& phone, uint64_t lobby,
	                         RsGxsId& id );

	/// Phone side: whether peer is a home that serves this phone.
	bool isHome(const RsPeerId& peer);

	/// Phone side: whether to dial peer. A phone in background dials only
	/// the friends that served it as a home, once it knows one: each dial to
	/// a friend that is away keeps its radio up for seconds, and it dials
	/// its friends every few minutes, on every address they ever had.
	bool wantsDial(const RsPeerId& peer);

	/// The chat service, which signs a phone's lobby keep-alives in advance
	/// and sends them for it on its home. Set once at start-up.
	void setChatService(DistributedChatService* chat) { mChat = chat; }

	/// Platform hooks, set by the Android service before the first login:
	/// sleepAllowedChanged(true) when this phone may sleep (in background,
	/// with a connected home that serves it), false when it must stay
	/// awake; wakeUp() when something arrives while it may sleep, so that
	/// the platform keeps it awake long enough to handle it. Called on
	/// libretroshare's threads.
	static void setPlatformHooks( std::function<void(bool)> sleepAllowedChanged,
	                              std::function<void()> wakeUp );

	/// Called for every item received from peer (pqiperson). Cheap unless
	/// this phone may sleep.
	void noteIncoming(const RsPeerId& peer);

	/// Called for every item sent to or received from peer (pqiperson). The
	/// items of the quiet links are counted per service, and tick() logs the
	/// counts every ten minutes: what still wakes a phone in background
	/// shows in the logs of both ends. Cheap while no link is quiet.
	void noteTraffic( const RsPeerId& peer, bool outgoing, uint16_t service,
	                  uint8_t subtype, uint32_t size );

	// p3FastService
	int tick() override;
	bool recvItem(RsItem* item) override;

	// pqiServiceMonitor
	void statusChange(const std::list<pqiServicePeer>& plist) override;

protected:
	// p3Config
	RsSerialiser* setupSerialiser() override;
	bool saveList(bool& cleanup, std::list<RsItem*>& lst) override;
	bool loadList(std::list<RsItem*>& load) override;

private:
	/// What a phone knows of a connected friend that runs MobileLink.
	struct HomeState
	{
		bool mHelloSent = false;
		bool mServing = false;
		rstime_t mLastPong = 0;
		uint32_t mLastPongSeq = 0;
	};

	/// What a home knows of a phone among its connected friends.
	struct PhoneState
	{
		std::set<RsGxsId> mOwnIds;
		std::map<uint64_t, RsGxsId> mLobbyIds;

		/// The tunnel hashes of distant messages to the phone's identities
		/// (p3GRouter::makeTunnelHash()).
		std::set<TurtleFileHash> mGRouterHashes;

		bool mQuiet = false;
		rstime_t mQuietEndedAt = 0;

		/// Whether the phone acknowledges the lobby lines kept for it.
		bool mAcksHeld = false;
		uint32_t mKeepAliveInterval = 0;
		rstime_t mLastHello = 0;
		rstime_t mLastPing = 0;

		/// The phone's lobby keep-alives signed in advance, by send time.
		std::multimap<rstime_t, RsMobileLinkKeepAlive> mKeepAliveStock;
	};

	void handleHello(const RsMobileLinkHelloItem& item);
	void handleHome(const RsMobileLinkHomeItem& item);
	void handleState(const RsMobileLinkStateItem& item);
	void handlePing(const RsMobileLinkPingItem& item);
	void handleHeldEnd(const RsMobileLinkHeldEndItem& item);
	void handleHeldAck(const RsMobileLinkHeldAckItem& item);
	void handlePong(const RsMobileLinkPongItem& item);
	void handleKeepAliveStock(const RsMobileLinkKeepAliveStockItem& item);

	/// Phone side, in background: sends the homes the lobby keep-alives of
	/// the coming hour when their stock runs short.
	void refillKeepAliveStock();

	/// Home side: sends the phones' keep-alives that are due.
	void releaseDueKeepAlives();

	void sendHello(const RsPeerId& home);
	void sendState(const RsPeerId& home);

	/// Sends a PING to every home; returns its sequence number, 0 when there
	/// is no home.
	uint32_t sendPings();

	/// Phone side: reads the phone's identities and lobby identities, and
	/// marks the HELLO to be sent again when they changed.
	void checkOwnIdentities();

	/// Home side: forgets the phones not heard from for a day.
	void forgetSilentPhones();

	/// Phone side: works out whether the phone may sleep and tells the
	/// platform when that changes.
	void updateSleepAllowed();

	void statusChangeLocked(const std::list<pqiServicePeer>& plist);

	/// Copies the peers on a quiet link into mQuietPeers.
	void updateQuietPeers();

	/// Logs the traffic counts of the quiet links, every ten minutes.
	void logQuietTraffic();

	struct TrafficCount
	{
		uint32_t mItems = 0;
		uint64_t mBytes = 0;
	};

	p3ServiceControl* mServiceControl;

	/// Guards everything below. A std::mutex for mPongReceived.
	std::mutex mMtx;
	std::condition_variable mPongReceived;

	bool mPhoneMode = false;
	bool mQuiet = false;

	/// When the phone last left the background. The link keeps its long
	/// silence allowance a little longer: see silenceTolerance().
	rstime_t mQuietEndedAt = 0;
	bool mServePhones = true;
	uint32_t mKeepAliveInterval;

	/// Phone side, per connected friend that runs MobileLink.
	std::map<RsPeerId, HomeState> mHomes;

	/// Phone side: the friends that said they serve this phone, connected or
	/// not. Saved.
	std::set<RsPeerId> mKnownHomes;

	/// Phone side: when a known home that is not connected is dialed next,
	/// and the delay that led there.
	struct HomeDial
	{
		rstime_t mNext = 0;
		rstime_t mDelay = 0;
	};
	std::map<RsPeerId, HomeDial> mHomeDials;

	/// Phone side: dials the known homes that are not connected.
	void dialMissingHomes();

	/// Phone side: what the last HELLO said.
	std::vector<RsGxsId> mOwnIds;
	std::map<uint64_t, RsGxsId> mLobbyIds;
	rstime_t mLastIdentityCheck = 0;
	uint32_t mPingSeq = 0;
	rstime_t mLastPingSent = 0;

	/// Phone side: the send time of the last keep-alive given to the homes.
	rstime_t mStockUntil = 0;

	/// The home that holds the keep-alive stock. One is enough: each home
	/// would release the same keep-alives into the same lobbies.
	RsPeerId mStockHome;

	DistributedChatService* mChat = nullptr;

	std::atomic<bool> mSleepAllowed{false};
	std::atomic<rstime_t> mLastWakeUp{0};
	static std::function<void(bool)> sSleepAllowedChanged;
	static std::function<void()> sWakeUp;

	/// Home side, per phone among the friends, connected or not: a phone
	/// keeps its state across a reconnection.
	std::map<RsPeerId, PhoneState> mPhones;

	/// Guards the traffic counts. Nothing is called while it is held, so
	/// that the hooks of pqiperson may take it on any thread.
	std::mutex mTrafficMtx;
	std::atomic<bool> mAnyQuietLink{false};
	std::set<RsPeerId> mQuietPeers;

	/// Per peer on a quiet link, per direction, service and subtype
	/// (outgoing << 24 | service << 8 | subtype).
	std::map<RsPeerId, std::map<uint32_t, TrafficCount>> mQuietTraffic;
	rstime_t mLastTrafficLog = 0;
};
