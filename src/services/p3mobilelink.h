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

#include <condition_variable>
#include <cstdint>
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

	/// How long the connection to peer may stay silent before it is taken
	/// for dead, in seconds; 0 for the usual timeouts. A phone in background
	/// and its home send each other only the phone's keep-alive and its
	/// answer, so they need much longer than the heartbeat's timeouts.
	rstime_t silenceTolerance(const RsPeerId& peer);

	/// Whether to send peer the periodic heartbeat. Not between a phone in
	/// background and its home: the phone's keep-alive replaces it.
	bool wantsHeartbeat(const RsPeerId& peer);

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
		uint32_t mKeepAliveInterval = 0;
		rstime_t mLastHello = 0;
		rstime_t mLastPing = 0;
	};

	void handleHello(const RsMobileLinkHelloItem& item);
	void handleHome(const RsMobileLinkHomeItem& item);
	void handleState(const RsMobileLinkStateItem& item);
	void handlePing(const RsMobileLinkPingItem& item);
	void handlePong(const RsMobileLinkPongItem& item);

	void sendHello(const RsPeerId& home);
	void sendState(const RsPeerId& home);

	/// Phone side: reads the phone's identities and lobby identities, and
	/// marks the HELLO to be sent again when they changed.
	void checkOwnIdentities();

	p3ServiceControl* mServiceControl;

	/// Guards everything below. A std::mutex for mPongReceived.
	std::mutex mMtx;
	std::condition_variable mPongReceived;

	bool mPhoneMode = false;
	bool mQuiet = false;
	bool mServePhones = true;
	uint32_t mKeepAliveInterval;

	/// Phone side, per connected friend that runs MobileLink.
	std::map<RsPeerId, HomeState> mHomes;

	/// Phone side: what the last HELLO said.
	std::vector<RsGxsId> mOwnIds;
	std::map<uint64_t, RsGxsId> mLobbyIds;
	rstime_t mLastIdentityCheck = 0;
	uint32_t mPingSeq = 0;

	/// Home side, per phone among the connected friends.
	std::map<RsPeerId, PhoneState> mPhones;
};
