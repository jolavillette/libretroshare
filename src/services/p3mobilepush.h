/*******************************************************************************
 * libretroshare/src/services: p3mobilepush.h                                  *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the                 *
 * GNU Lesser General Public License for more details.                         *
 *                                                                             *
 * You should have received a copy of the GNU Lesser General Public License    *
 * along with this program. If not, see <https://www.gnu.org/licenses/>.       *
 *                                                                             *
 *******************************************************************************/
#pragma once

#include <cstdint>
#include <list>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "pqi/p3cfgmgr.h"
#include "pqi/pqiservicemonitor.h"
#include "retroshare/rsmobilepush.h"
#include "rsitems/rsmobilepushitems.h"
#include "services/p3service.h"
#include "util/rstime.h"

class p3MobileLink;
class p3ServiceControl;
class RsChatLobbyMsgItem;

/**
 * The MobilePush service, in both its roles.
 *
 * On a phone it sends the registration the application set to each friend
 * that MobileLink knows as a home.
 *
 * On a home it records the registrations of the phones among its friends.
 * When the chat service keeps a lobby line for a phone, it seals the line
 * with the phone's key and queues it for the sender process, which reads the
 * queue through RsMobilePush.
 */
class p3MobilePush: public RsMobilePush, public p3FastService,
        public p3Config, public pqiServiceMonitor
{
public:
	p3MobilePush(p3ServiceControl* serviceControl, p3MobileLink* mobileLink);

	RsServiceInfo getServiceInfo() override;

	// RsMobilePush
	bool setRegistration(const RsMobilePushRegistration& registration) override;
	void getRegistration(RsMobilePushRegistration& registration) override;
	void getRegisteredPhones(std::vector<RsPeerId>& phones) override;
	void getPendingNotifications(
	        std::vector<RsMobilePushNotification>& notifications ) override;
	void acknowledgeNotifications(const std::vector<uint32_t>& ids) override;
	void setLobbyMode(uint64_t lobbyId, RsMobilePushLobbyMode mode) override;
	void getLobbyModes(
	        std::map<uint64_t, RsMobilePushLobbyMode>& modes ) override;
	void setDefaultLobbyMode(RsMobilePushLobbyMode mode) override;
	RsMobilePushLobbyMode getDefaultLobbyMode() override;

	/// Home side: the chat service kept line of lobby lobbyName for phone.
	/// Called with the chat service's mutex held: it only seals and queues.
	void lineHeldForPhone( const RsPeerId& phone, uint64_t lobby,
	                       const std::string& lobbyName,
	                       const RsChatLobbyMsgItem& line );

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
	/// What a home knows of a registered phone.
	struct PhoneState
	{
		RsMobilePushRegistration mRegistration;

		/// How many notifications the phone may still get at once, and when
		/// that was last worked out: see lineHeldForPhone().
		double mAllowance = 0;
		rstime_t mAllowanceTime = 0;
	};

	void handleRegistration( const RsPeerId& peer,
	                         const RsMobilePushRegistration& registration );

	/// Phone side: sends the registration to the homes that do not have it.
	void sendRegistrationToHomes();

	p3ServiceControl* mServiceControl;
	p3MobileLink* mMobileLink;

	/// Guards everything below.
	std::mutex mMtx;

	/// Phone side.
	RsMobilePushRegistration mRegistration;

	/// Phone side: the connected friends that do not have the registration
	/// yet. A friend gets it once MobileLink knows it as a home.
	std::set<RsPeerId> mToRegisterWith;

	/// Home side. Saved.
	std::map<RsPeerId, PhoneState> mPhones;

	/// Home side: which lines notify, per lobby and for the others. Saved.
	std::map<uint64_t, RsMobilePushLobbyMode> mLobbyModes;
	RsMobilePushLobbyMode mDefaultLobbyMode = RsMobilePushLobbyMode::ALL;

	/// Home side, oldest first.
	std::list<RsMobilePushNotification> mQueue;
	uint32_t mNextId = 1;

	rstime_t mLastTick = 0;
};
