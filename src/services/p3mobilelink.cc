/*******************************************************************************
 * libretroshare/src/services: p3mobilelink.cc                                 *
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
#include "services/p3mobilelink.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iterator>
#include <sstream>
#include <string>

#include "chat/distributedchat.h"
#include "chat/rschatitems.h"
#include "grouter/groutertypes.h"
#include "grouter/p3grouter.h"
#include "gxstunnel/p3gxstunnel.h"
#include "pqi/p3cfgmgr.h"
#include "pqi/p3servicecontrol.h"
#include "retroshare/rschats.h"
#include "retroshare/rsidentity.h"
#include "retroshare/rspeers.h"
#include "retroshare/rsiface.h"
#include "rsitems/rsconfigitems.h"
#include "util/rsdebug.h"

RsMobileLink* rsMobileLink = nullptr;

std::function<void(bool)> p3MobileLink::sSleepAllowedChanged;
std::function<void()> p3MobileLink::sWakeUp;

RsMobileLink::~RsMobileLink() = default;

/// How often a phone looks whether its identities or lobbies changed.
static const rstime_t IDENTITY_CHECK_PERIOD = 60;

/// A phone's keep-alive interval by default. Mobile networks forget an idle
/// connection after a few minutes; the app adjusts it to the network.
static const uint32_t DEFAULT_KEEP_ALIVE_INTERVAL = 240;

/// A home forgets a phone it has not heard from for this long.
static const rstime_t FORGET_PHONE_AFTER = 86400;

/// The chat lobby keep-alive interval (MAX_DELAY_BETWEEN_LOBBY_KEEP_ALIVE in
/// chat/distributedchat.cc).
static const rstime_t LOBBY_KEEP_ALIVE_INTERVAL = 120;

/// A phone in background gives its homes its lobby keep-alives for this long
/// ahead, and gives the next ones when less than half of it is left. Its
/// presence in the lobbies outlives it by at most that long.
static const rstime_t KEEP_ALIVE_STOCK_AHEAD = 3600;

/// The most keep-alives a home keeps for a phone.
static const size_t MAX_STOCKED_KEEP_ALIVES = 2000;

/// A phone that may sleep asks the platform to keep it awake at most this
/// often when items arrive.
static const rstime_t MIN_WAKE_UP_INTERVAL = 2;

/// The silence a phone in background and its home accept from each other:
/// three keep-alive intervals, and never less than this.
static const rstime_t MIN_SILENCE_TOLERANCE = 900;

/// How often each end logs what its quiet links carried.
static const rstime_t QUIET_TRAFFIC_LOG_PERIOD = 600;

/// Seconds a link keeps its long silence allowance after the phone left
/// the background.
static const rstime_t BACK_FROM_QUIET_GRACE = 120;

/// A phone dials a home it lost after this many seconds, then doubles the
/// delay at each failure up to the maximum. The link manager alone tries
/// every 140 s at best, which leaves a phone with a single home cut off for
/// minutes after each change of network or restart of the home.
static const rstime_t HOME_DIAL_FIRST_DELAY = 5;
static const rstime_t HOME_DIAL_MAX_DELAY = 120;

static rstime_t silenceToleranceFor(uint32_t keepAliveInterval)
{
	return std::max<rstime_t>( MIN_SILENCE_TOLERANCE,
	                           3 * static_cast<rstime_t>(keepAliveInterval) );
}

static const std::string MOBILE_LINK_APP_NAME = "mobilelink";
static const uint16_t MOBILE_LINK_APP_MAJOR_VERSION = 1;
static const uint16_t MOBILE_LINK_APP_MINOR_VERSION = 0;
static const uint16_t MOBILE_LINK_MIN_MAJOR_VERSION = 1;
static const uint16_t MOBILE_LINK_MIN_MINOR_VERSION = 0;

p3MobileLink::p3MobileLink(p3ServiceControl* serviceControl):
    mServiceControl(serviceControl),
    mKeepAliveInterval(DEFAULT_KEEP_ALIVE_INTERVAL)
{
	addSerialType(new RsMobileLinkSerialiser());
}

RsServiceInfo p3MobileLink::getServiceInfo()
{
	return RsServiceInfo( static_cast<uint16_t>(RsServiceType::MOBILE_LINK),
	                      MOBILE_LINK_APP_NAME,
	                      MOBILE_LINK_APP_MAJOR_VERSION,
	                      MOBILE_LINK_APP_MINOR_VERSION,
	                      MOBILE_LINK_MIN_MAJOR_VERSION,
	                      MOBILE_LINK_MIN_MINOR_VERSION );
}

/******************************************************************************/
/*                               RsMobileLink                                 */
/******************************************************************************/

void p3MobileLink::setPhoneMode(bool phone)
{
	std::vector<RsPeerId> homes;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(mPhoneMode == phone) return;

		mPhoneMode = phone;
		if(!phone) mQuiet = false;

		// The homes learn the new mode at once; a new phone also sends its
		// identities at the next tick.
		for(auto& home: mHomes)
		{
			home.second.mHelloSent = false;
			homes.push_back(home.first);
		}
		mLastIdentityCheck = 0;
	}
	RsInfo() << "MobileLink: phone mode " << (phone ? "on" : "off");

	if(!phone)
		for(const RsPeerId& home: homes) sendState(home);

	updateSleepAllowed();
	IndicateConfigChanged();
}

bool p3MobileLink::getPhoneMode()
{
	std::lock_guard<std::mutex> lock(mMtx);
	return mPhoneMode;
}

void p3MobileLink::setQuiet(bool quiet)
{
	std::vector<RsPeerId> homes;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(!mPhoneMode || mQuiet == quiet) return;

		mQuiet = quiet;
		if(!quiet)
		{
			mStockUntil = 0;
			mQuietEndedAt = time(nullptr);

			// The user is back: a missing home is dialed at the next tick.
			for(auto& dial: mHomeDials)
			{
				dial.second.mDelay = HOME_DIAL_FIRST_DELAY;
				dial.second.mNext = 1;
			}
		}
		for(const auto& home: mHomes) homes.push_back(home.first);
	}
	RsInfo() << "MobileLink: " << (quiet ? "quiet" : "active");

	for(const RsPeerId& home: homes) sendState(home);
	updateSleepAllowed();

	// In background the phone asked nobody for the lobby list, and the core
	// keeps a lobby it is not in for a minute only: ask at once, so the list
	// is there when the user opens it.
	if(!quiet && mChat) mChat->requestLobbyListNow();

	// The system may end a phone's process in background without notice,
	// and most of the configuration is saved only at shutdown or once an
	// hour: a lobby joined meanwhile would be gone at the next start, while
	// the home goes on keeping its lines. Save now what changed.
	if(quiet)
		if(auto manager = dynamic_cast<p3ConfigMgr*>(RsControl::instance()->configManager()))
			manager->saveConfiguration();
}

bool p3MobileLink::getQuiet()
{
	std::lock_guard<std::mutex> lock(mMtx);
	return mQuiet;
}

void p3MobileLink::setKeepAliveInterval(uint32_t seconds)
{
	std::vector<RsPeerId> homes;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(seconds == 0 || mKeepAliveInterval == seconds) return;

		mKeepAliveInterval = seconds;
		if(mPhoneMode)
			for(const auto& home: mHomes) homes.push_back(home.first);
	}

	for(const RsPeerId& home: homes) sendState(home);

	IndicateConfigChanged();
}

uint32_t p3MobileLink::getKeepAliveInterval()
{
	std::lock_guard<std::mutex> lock(mMtx);
	return mKeepAliveInterval;
}

uint32_t p3MobileLink::sendPings()
{
	std::vector<RsPeerId> homes;
	uint32_t seq;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		for(const auto& home: mHomes) homes.push_back(home.first);
		if(homes.empty()) return 0;

		seq = ++mPingSeq;
		if(seq == 0) seq = ++mPingSeq;
		mLastPingSent = time(nullptr);
	}

	for(const RsPeerId& home: homes)
	{
		auto ping = new RsMobileLinkPingItem();
		ping->PeerId(home);
		ping->mSeq = seq;
		sendItem(ping);
	}
	return seq;
}

bool p3MobileLink::keepAliveNow(uint32_t timeoutSeconds)
{
	uint32_t seq = sendPings();
	if(seq == 0) return false;

	std::unique_lock<std::mutex> lock(mMtx);
	return mPongReceived.wait_for(
	            lock, std::chrono::seconds(timeoutSeconds), [this, seq]()
	{
		for(const auto& home: mHomes)
			if(home.second.mLastPongSeq == seq) return true;
		return false;
	} );
}

void p3MobileLink::getHomes(std::vector<RsMobileLinkHomeInfo>& homes)
{
	homes.clear();

	std::lock_guard<std::mutex> lock(mMtx);
	for(const auto& home: mHomes)
	{
		RsMobileLinkHomeInfo info;
		info.mPeerId = home.first;
		info.mServing = home.second.mServing;
		info.mLastPong = home.second.mLastPong;
		homes.push_back(info);
	}
}

void p3MobileLink::setServePhones(bool serve)
{
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(mServePhones == serve) return;

		mServePhones = serve;

		// A phone sends its HELLO again at its next connection.
		if(!serve) mPhones.clear();
	}
	RsInfo() << "MobileLink: serving phones " << (serve ? "on" : "off");

	IndicateConfigChanged();
}

bool p3MobileLink::getServePhones()
{
	std::lock_guard<std::mutex> lock(mMtx);
	return mServePhones;
}

void p3MobileLink::getPhones(std::vector<RsMobileLinkPhoneInfo>& phones)
{
	phones.clear();

	std::lock_guard<std::mutex> lock(mMtx);
	for(const auto& phone: mPhones)
	{
		RsMobileLinkPhoneInfo info;
		info.mPeerId = phone.first;
		info.mQuiet = phone.second.mQuiet;
		info.mKeepAliveInterval = phone.second.mKeepAliveInterval;
		info.mLastHello = phone.second.mLastHello;
		info.mLastPing = phone.second.mLastPing;
		info.mOwnIds.assign( phone.second.mOwnIds.begin(),
		                     phone.second.mOwnIds.end() );
		info.mLobbyIds = phone.second.mLobbyIds;
		phones.push_back(info);
	}
}

/******************************************************************************/
/*                     Questions from the other services                      */
/******************************************************************************/

bool p3MobileLink::wantsTunnelRequest( const RsPeerId& peer,
                                       const TurtleFileHash& hash )
{
	std::lock_guard<std::mutex> lock(mMtx);

	auto it = mPhones.find(peer);
	if(it == mPhones.end()) return true;

	const PhoneState& phone = it->second;

	// Distant messages: the hash is computed from the destination identity.
	if(phone.mGRouterHashes.count(hash)) return true;

	// Distant chat: the destination identity is in clear in the hash.
	return phone.mOwnIds.count(
	            p3GxsTunnelService::destinationGxsIdFromHash(hash) ) > 0;
}

bool p3MobileLink::wantsSearchRequest(const RsPeerId& peer)
{
	std::lock_guard<std::mutex> lock(mMtx);
	return mPhones.find(peer) == mPhones.end();
}

bool p3MobileLink::isQuietPhone(const RsPeerId& peer)
{
	std::lock_guard<std::mutex> lock(mMtx);

	auto it = mPhones.find(peer);
	return it != mPhones.end() && it->second.mQuiet;
}

bool p3MobileLink::localQuiet()
{
	std::lock_guard<std::mutex> lock(mMtx);
	return mPhoneMode && mQuiet;
}

rstime_t p3MobileLink::silenceTolerance(const RsPeerId& peer)
{
	std::lock_guard<std::mutex> lock(mMtx);

	// A link that was silent for minutes is not dead the second the phone
	// is back: its last packet is as old as the silence, and with the usual
	// 60 s allowance the phone cut the link at each wake, at the very moment
	// its home sent it what it had kept. The allowance stays until the
	// traffic of an active link has had time to start again.
	rstime_t now = time(nullptr);

	// Home side: a phone in background.
	auto phone = mPhones.find(peer);
	if(phone != mPhones.end() &&
	   (phone->second.mQuiet || now < phone->second.mQuietEndedAt + BACK_FROM_QUIET_GRACE))
		return silenceToleranceFor(phone->second.mKeepAliveInterval);

	// Phone side: its homes while it is in background.
	if(mPhoneMode && mHomes.count(peer) &&
	   (mQuiet || now < mQuietEndedAt + BACK_FROM_QUIET_GRACE))
		return silenceToleranceFor(mKeepAliveInterval);

	return 0;
}

bool p3MobileLink::phoneLobbyIdentity( const RsPeerId& phone, uint64_t lobby,
                                       RsGxsId& id )
{
	std::lock_guard<std::mutex> lock(mMtx);

	auto it = mPhones.find(phone);
	if(it == mPhones.end()) return false;

	auto lit = it->second.mLobbyIds.find(lobby);
	if(lit == it->second.mLobbyIds.end()) return false;

	id = lit->second;
	return true;
}

bool p3MobileLink::isHome(const RsPeerId& peer)
{
	std::lock_guard<std::mutex> lock(mMtx);

	auto it = mHomes.find(peer);
	return mPhoneMode && it != mHomes.end() && it->second.mServing;
}

bool p3MobileLink::wantsDial(const RsPeerId& peer)
{
	std::lock_guard<std::mutex> lock(mMtx);

	if(!mPhoneMode || !mQuiet || mKnownHomes.empty()) return true;
	return mKnownHomes.count(peer) > 0;
}

bool p3MobileLink::wantsHeartbeat(const RsPeerId& peer)
{
	return !isQuietLink(peer);
}

bool p3MobileLink::isQuietLink(const RsPeerId& peer)
{
	std::lock_guard<std::mutex> lock(mMtx);

	auto phone = mPhones.find(peer);
	if(phone != mPhones.end() && phone->second.mQuiet) return true;

	return mPhoneMode && mQuiet && mHomes.count(peer);
}

/******************************************************************************/
/*                                  Items                                     */
/******************************************************************************/

int p3MobileLink::tick()
{
	checkOwnIdentities();
	forgetSilentPhones();

	// A phone in background sends its keep-alive itself while it runs. When
	// the phone may sleep, the app's alarm calls keepAliveNow() instead.
	bool keepAliveDue;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		keepAliveDue = mPhoneMode && mQuiet &&
		        time(nullptr) >= mLastPingSent + static_cast<rstime_t>(mKeepAliveInterval);
	}
	if(keepAliveDue) sendPings();

	dialMissingHomes();
	refillKeepAliveStock();
	releaseDueKeepAlives();
	updateQuietPeers();
	logQuietTraffic();

	std::vector<RsPeerId> helloTo;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(!mPhoneMode) return 0;

		for(auto& home: mHomes)
			if(!home.second.mHelloSent)
			{
				home.second.mHelloSent = true;
				helloTo.push_back(home.first);
			}
	}

	for(const RsPeerId& home: helloTo)
	{
		sendHello(home);
		sendState(home);

		// This phone acknowledges the lobby lines its home keeps for it.
		auto ack = new RsMobileLinkHeldAckItem();
		ack->PeerId(home);
		sendItem(ack);
	}

	return 0;
}

void p3MobileLink::dialMissingHomes()
{
	std::vector<RsPeerId> dial;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(!mPhoneMode)
		{
			mHomeDials.clear();
			return;
		}

		// A phone asleep does not tick: there the next dial happens at its
		// next wake, whatever the delay says.
		rstime_t now = time(nullptr);
		for(const RsPeerId& home: mKnownHomes)
		{
			if(mHomes.count(home))
			{
				mHomeDials.erase(home);
				continue;
			}

			HomeDial& state = mHomeDials[home];
			if(state.mNext == 0)
			{
				state.mDelay = HOME_DIAL_FIRST_DELAY;
				state.mNext = now + state.mDelay;
				continue;
			}
			if(now < state.mNext) continue;

			dial.push_back(home);
			state.mDelay = std::min(2 * state.mDelay, HOME_DIAL_MAX_DELAY);
			state.mNext = now + state.mDelay;
		}
	}

	// Outside the lock: the link manager calls this service back.
	if(rsPeers)
		for(const RsPeerId& home: dial) rsPeers->connectAttempt(home);
}

void p3MobileLink::setPlatformHooks( std::function<void(bool)> sleepAllowedChanged,
                                     std::function<void()> wakeUp )
{
	sSleepAllowedChanged = std::move(sleepAllowedChanged);
	sWakeUp = std::move(wakeUp);
}

void p3MobileLink::noteIncoming(const RsPeerId& /*peer*/)
{
	if(!mSleepAllowed) return;

	rstime_t now = time(nullptr);
	rstime_t last = mLastWakeUp;
	if(now < last + MIN_WAKE_UP_INTERVAL) return;
	if(!mLastWakeUp.compare_exchange_strong(last, now)) return;

	if(sWakeUp) sWakeUp();
}

void p3MobileLink::noteTraffic( const RsPeerId& peer, bool outgoing,
                                uint16_t service, uint8_t subtype,
                                uint32_t size )
{
	if(!mAnyQuietLink) return;

	std::lock_guard<std::mutex> lock(mTrafficMtx);
	if(!mQuietPeers.count(peer)) return;

	uint32_t key = (outgoing ? 1u << 24 : 0u) |
	        (static_cast<uint32_t>(service) << 8) | subtype;
	TrafficCount& count = mQuietTraffic[peer][key];
	++count.mItems;
	count.mBytes += size;
}

void p3MobileLink::updateQuietPeers()
{
	std::set<RsPeerId> quietPeers;
	{
		std::lock_guard<std::mutex> lock(mMtx);

		for(const auto& phone: mPhones)
			if(phone.second.mQuiet) quietPeers.insert(phone.first);

		if(mPhoneMode && mQuiet)
			for(const auto& home: mHomes) quietPeers.insert(home.first);
	}

	std::lock_guard<std::mutex> lock(mTrafficMtx);
	mAnyQuietLink = !quietPeers.empty();
	mQuietPeers.swap(quietPeers);
}

void p3MobileLink::logQuietTraffic()
{
	rstime_t now = time(nullptr);
	rstime_t period;
	std::set<RsPeerId> quietPeers;
	std::map<RsPeerId, std::map<uint32_t, TrafficCount>> traffic;
	{
		std::lock_guard<std::mutex> lock(mTrafficMtx);

		if(!mLastTrafficLog) mLastTrafficLog = now;
		if(now < mLastTrafficLog + QUIET_TRAFFIC_LOG_PERIOD) return;

		period = now - mLastTrafficLog;
		mLastTrafficLog = now;
		quietPeers = mQuietPeers;
		traffic.swap(mQuietTraffic);
	}

	// The peers still quiet, even if nothing passed, and the peers that
	// were quiet for part of the period.
	for(const auto& peerTraffic: traffic) quietPeers.insert(peerTraffic.first);

	for(const RsPeerId& peer: quietPeers)
	{
		uint32_t items[2] = { 0, 0 };
		uint64_t bytes[2] = { 0, 0 };
		std::ostringstream detail[2];

		auto it = traffic.find(peer);
		if(it != traffic.end())
			for(const auto& count: it->second)
			{
				int out = (count.first >> 24) ? 1 : 0;
				items[out] += count.second.mItems;
				bytes[out] += count.second.mBytes;
				detail[out] << " " << std::hex << ((count.first >> 8) & 0xffff)
				            << "/" << (count.first & 0xff) << std::dec << ":"
				            << count.second.mItems << "x" << count.second.mBytes
				            << "B";
			}

		RsInfo() << "MobileLink: quiet link with " << peer << ", last "
		         << period << " s: sent " << items[1] << " items " << bytes[1]
		         << " B (service/subtype:items x bytes" << detail[1].str()
		         << "), received " << items[0] << " items " << bytes[0]
		         << " B (" << detail[0].str() << " )";
	}
}

void p3MobileLink::updateSleepAllowed()
{
	bool allowed = false;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(mPhoneMode && mQuiet)
			for(const auto& home: mHomes)
				if(home.second.mServing) { allowed = true; break; }
	}

	if(mSleepAllowed.exchange(allowed) == allowed) return;

	RsInfo() << "MobileLink: the phone " << (allowed ? "may sleep" : "stays awake");
	if(sSleepAllowedChanged) sSleepAllowedChanged(allowed);
}

void p3MobileLink::forgetSilentPhones()
{
	std::lock_guard<std::mutex> lock(mMtx);

	rstime_t now = time(nullptr);
	for(auto it = mPhones.begin(); it != mPhones.end();)
	{
		rstime_t lastHeard = std::max(it->second.mLastHello, it->second.mLastPing);
		if(lastHeard + FORGET_PHONE_AFTER < now) it = mPhones.erase(it);
		else ++it;
	}
}

void p3MobileLink::checkOwnIdentities()
{
	{
		std::lock_guard<std::mutex> lock(mMtx);

		// Identities and lobbies do not change while the phone is in
		// background.
		if(!mPhoneMode || mQuiet) return;

		rstime_t now = time(nullptr);
		if(now < mLastIdentityCheck + IDENTITY_CHECK_PERIOD) return;
		mLastIdentityCheck = now;
	}

	std::vector<RsGxsId> ownIds;
	if(rsIdentity)
	{
		std::vector<RsGxsId> ids;
		if(rsIdentity->getOwnSignedIds(ids))
			ownIds.insert(ownIds.end(), ids.begin(), ids.end());
		ids.clear();
		if(rsIdentity->getOwnPseudonimousIds(ids))
			ownIds.insert(ownIds.end(), ids.begin(), ids.end());
	}

	std::map<uint64_t, RsGxsId> lobbyIds;
	if(rsChats)
	{
		std::list<ChatLobbyId> lobbies;
		rsChats->getChatLobbyList(lobbies);
		for(ChatLobbyId lobby: lobbies)
		{
			ChatLobbyInfo info;
			if(rsChats->getChatLobbyInfo(lobby, info))
				lobbyIds[lobby] = info.gxs_id;
		}
	}

	std::lock_guard<std::mutex> lock(mMtx);
	if(ownIds == mOwnIds && lobbyIds == mLobbyIds) return;

	mOwnIds = ownIds;
	mLobbyIds = lobbyIds;
	for(auto& home: mHomes) home.second.mHelloSent = false;
}

void p3MobileLink::sendHello(const RsPeerId& home)
{
	auto hello = new RsMobileLinkHelloItem();
	hello->PeerId(home);
	{
		std::lock_guard<std::mutex> lock(mMtx);
		hello->mOwnIds = mOwnIds;
		hello->mLobbyIds = mLobbyIds;
	}
	sendItem(hello);
}

void p3MobileLink::sendState(const RsPeerId& home)
{
	auto state = new RsMobileLinkStateItem();
	state->PeerId(home);
	{
		std::lock_guard<std::mutex> lock(mMtx);
		state->mPhone = mPhoneMode;
		state->mQuiet = mQuiet;
		state->mKeepAliveInterval = mKeepAliveInterval;
	}
	sendItem(state);
}

bool p3MobileLink::recvItem(RsItem* item)
{
	switch(item->PacketSubType())
	{
	case RS_PKT_SUBTYPE_MOBILE_LINK_HELLO:
		if(auto hello = dynamic_cast<RsMobileLinkHelloItem*>(item))
			handleHello(*hello);
		break;
	case RS_PKT_SUBTYPE_MOBILE_LINK_HOME:
		if(auto home = dynamic_cast<RsMobileLinkHomeItem*>(item))
			handleHome(*home);
		break;
	case RS_PKT_SUBTYPE_MOBILE_LINK_STATE:
		if(auto state = dynamic_cast<RsMobileLinkStateItem*>(item))
			handleState(*state);
		break;
	case RS_PKT_SUBTYPE_MOBILE_LINK_PING:
		if(auto ping = dynamic_cast<RsMobileLinkPingItem*>(item))
			handlePing(*ping);
		break;
	case RS_PKT_SUBTYPE_MOBILE_LINK_PONG:
		if(auto pong = dynamic_cast<RsMobileLinkPongItem*>(item))
			handlePong(*pong);
		break;
	case RS_PKT_SUBTYPE_MOBILE_LINK_KEEP_ALIVE_STOCK:
		if(auto stock = dynamic_cast<RsMobileLinkKeepAliveStockItem*>(item))
			handleKeepAliveStock(*stock);
		break;
	case RS_PKT_SUBTYPE_MOBILE_LINK_HELD_END:
		if(auto end = dynamic_cast<RsMobileLinkHeldEndItem*>(item))
			handleHeldEnd(*end);
		break;
	case RS_PKT_SUBTYPE_MOBILE_LINK_HELD_ACK:
		if(auto ack = dynamic_cast<RsMobileLinkHeldAckItem*>(item))
			handleHeldAck(*ack);
		break;
	default:
		break;
	}

	delete item;
	return true;
}

void p3MobileLink::handleHello(const RsMobileLinkHelloItem& item)
{
	const RsPeerId& peer = item.PeerId();

	// The hashes are computed outside the lock: no other service is called
	// while it is held.
	std::set<TurtleFileHash> grouterHashes;
	for(const RsGxsId& id: item.mOwnIds)
		grouterHashes.insert(
		            p3GRouter::makeTunnelHash(id, GROUTER_CLIENT_ID_MESSAGES) );

	bool serving;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		serving = mServePhones;
		if(serving)
		{
			PhoneState& phone = mPhones[peer];
			phone.mOwnIds = std::set<RsGxsId>( item.mOwnIds.begin(),
			                                   item.mOwnIds.end() );
			phone.mLobbyIds = item.mLobbyIds;
			phone.mGRouterHashes = grouterHashes;
			phone.mLastHello = time(nullptr);
			phone.mAcksHeld = false;	// said again after each HELLO
		}
	}

	if(serving)
		RsInfo() << "MobileLink: friend " << peer << " is a phone with "
		         << item.mOwnIds.size() << " identities and "
		         << item.mLobbyIds.size() << " lobbies";

	auto answer = new RsMobileLinkHomeItem();
	answer->PeerId(peer);
	answer->mServing = serving;
	sendItem(answer);
}

void p3MobileLink::handleHome(const RsMobileLinkHomeItem& item)
{
	bool knownHomesChanged;
	{
		std::lock_guard<std::mutex> lock(mMtx);

		auto it = mHomes.find(item.PeerId());
		if(it != mHomes.end()) it->second.mServing = item.mServing;

		knownHomesChanged = item.mServing ?
		            mKnownHomes.insert(item.PeerId()).second :
		            mKnownHomes.erase(item.PeerId()) > 0;
	}
	if(knownHomesChanged) IndicateConfigChanged();
	updateSleepAllowed();
}

void p3MobileLink::handleState(const RsMobileLinkStateItem& item)
{
	std::lock_guard<std::mutex> lock(mMtx);

	if(!item.mPhone)
	{
		mPhones.erase(item.PeerId());
		return;
	}

	auto it = mPhones.find(item.PeerId());
	if(it == mPhones.end()) return;

	if(it->second.mQuiet && !item.mQuiet) it->second.mQuietEndedAt = time(nullptr);
	it->second.mQuiet = item.mQuiet;
	it->second.mKeepAliveInterval = item.mKeepAliveInterval;

	// Back to active, the phone sends its keep-alives itself again.
	if(!item.mQuiet) it->second.mKeepAliveStock.clear();
}

bool p3MobileLink::acknowledgesHeld(const RsPeerId& phone)
{
	std::lock_guard<std::mutex> lock(mMtx);

	auto it = mPhones.find(phone);
	return it != mPhones.end() && it->second.mAcksHeld;
}

void p3MobileLink::sendHeldEnd(const RsPeerId& phone, uint32_t batch)
{
	auto end = new RsMobileLinkHeldEndItem();
	end->PeerId(phone);
	end->mBatch = batch;
	sendItem(end);
}

void p3MobileLink::handleHeldEnd(const RsMobileLinkHeldEndItem& item)
{
	// The item travels behind the lines of its batch, at their priority:
	// they are all here.
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(!mPhoneMode || !mHomes.count(item.PeerId())) return;
	}

	auto ack = new RsMobileLinkHeldAckItem();
	ack->PeerId(item.PeerId());
	ack->mBatch = item.mBatch;
	sendItem(ack);
}

void p3MobileLink::handleHeldAck(const RsMobileLinkHeldAckItem& item)
{
	if(item.mBatch == 0)
	{
		std::lock_guard<std::mutex> lock(mMtx);

		auto it = mPhones.find(item.PeerId());
		if(it != mPhones.end()) it->second.mAcksHeld = true;
		return;
	}

	// Outside the lock: the chat service calls this service back.
	if(mChat) mChat->heldLinesAcknowledged(item.PeerId(), item.mBatch);
}

void p3MobileLink::handlePing(const RsMobileLinkPingItem& item)
{
	{
		std::lock_guard<std::mutex> lock(mMtx);

		auto it = mPhones.find(item.PeerId());
		if(it != mPhones.end()) it->second.mLastPing = time(nullptr);
	}

	auto pong = new RsMobileLinkPongItem();
	pong->PeerId(item.PeerId());
	pong->mSeq = item.mSeq;
	sendItem(pong);
}

void p3MobileLink::handlePong(const RsMobileLinkPongItem& item)
{
	{
		std::lock_guard<std::mutex> lock(mMtx);

		auto it = mHomes.find(item.PeerId());
		if(it == mHomes.end()) return;

		it->second.mLastPong = time(nullptr);
		it->second.mLastPongSeq = item.mSeq;
	}
	mPongReceived.notify_all();
}

void p3MobileLink::handleKeepAliveStock(const RsMobileLinkKeepAliveStockItem& item)
{
	std::lock_guard<std::mutex> lock(mMtx);

	auto it = mPhones.find(item.PeerId());
	if(!mServePhones || it == mPhones.end()) return;

	// Nothing already past, nothing too far ahead.
	rstime_t now = time(nullptr);
	auto& stock = it->second.mKeepAliveStock;
	for(const RsMobileLinkKeepAlive& keepAlive: item.mKeepAlives)
		if( static_cast<rstime_t>(keepAlive.mSendTime) + LOBBY_KEEP_ALIVE_INTERVAL >= now &&
		    static_cast<rstime_t>(keepAlive.mSendTime) <= now + 2 * KEEP_ALIVE_STOCK_AHEAD )
			stock.emplace(keepAlive.mSendTime, keepAlive);

	while(stock.size() > MAX_STOCKED_KEEP_ALIVES) stock.erase(std::prev(stock.end()));
}

void p3MobileLink::refillKeepAliveStock()
{
	RsPeerId stockHome;
	rstime_t from, until;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(!mPhoneMode || !mQuiet || !mChat) return;

		// The home that has the stock keeps it as long as it serves us;
		// when it goes, another one gets a new stock at once.
		auto current = mHomes.find(mStockHome);
		if(current == mHomes.end() || !current->second.mServing)
		{
			mStockHome.clear();
			for(const auto& home: mHomes)
				if(home.second.mServing) { mStockHome = home.first; break; }
			if(mStockHome.isNull()) return;
			mStockUntil = 0;
		}
		stockHome = mStockHome;

		rstime_t now = time(nullptr);
		if(mStockUntil > now + KEEP_ALIVE_STOCK_AHEAD / 2) return;

		// The phone sent its last keep-alive itself less than an interval
		// ago: the stock starts half an interval from now.
		from = mStockUntil ? mStockUntil + LOBBY_KEEP_ALIVE_INTERVAL
		                   : now + LOBBY_KEEP_ALIVE_INTERVAL / 2;
		until = now + KEEP_ALIVE_STOCK_AHEAD;
		if(from > until) return;
	}

	uint32_t count = static_cast<uint32_t>((until - from) / LOBBY_KEEP_ALIVE_INTERVAL) + 1;

	std::vector<RsMobileLinkKeepAlive> keepAlives;
	std::list<ChatLobbyId> lobbies;
	mChat->getChatLobbyList(lobbies);
	for(ChatLobbyId lobby: lobbies)
	{
		std::list<RsChatLobbyEventItem*> items;
		mChat->makePresignedKeepAlives(lobby, from, count, items);
		for(RsChatLobbyEventItem* event: items)
		{
			RsMobileLinkKeepAlive keepAlive;
			keepAlive.mLobbyId = event->lobby_id;
			keepAlive.mMsgId = event->msg_id;
			keepAlive.mNick = event->nick;
			keepAlive.mSendTime = event->sendTime;
			keepAlive.mSignature = event->signature;
			keepAlives.push_back(keepAlive);
			delete event;
		}
	}

	{
		std::lock_guard<std::mutex> lock(mMtx);
		mStockUntil = from + static_cast<rstime_t>(count - 1) * LOBBY_KEEP_ALIVE_INTERVAL;
	}
	if(keepAlives.empty()) return;

	auto stock = new RsMobileLinkKeepAliveStockItem();
	stock->PeerId(stockHome);
	stock->mKeepAlives = keepAlives;
	sendItem(stock);
}

void p3MobileLink::releaseDueKeepAlives()
{
	if(!mChat) return;

	std::vector<std::pair<RsPeerId, RsMobileLinkKeepAlive>> due;
	{
		std::lock_guard<std::mutex> lock(mMtx);

		rstime_t now = time(nullptr);
		for(auto& phone: mPhones)
		{
			auto& stock = phone.second.mKeepAliveStock;
			auto end = stock.upper_bound(now);
			for(auto it = stock.begin(); it != end; ++it)
				due.emplace_back(phone.first, it->second);
			stock.erase(stock.begin(), end);
		}
	}

	// Outside the lock: the chat service calls this service back.
	for(const auto& keepAlive: due)
	{
		auto event = new RsChatLobbyEventItem();
		event->event_type = RS_CHAT_LOBBY_EVENT_KEEP_ALIVE;
		event->sendTime = keepAlive.second.mSendTime;
		event->lobby_id = keepAlive.second.mLobbyId;
		event->msg_id = keepAlive.second.mMsgId;
		event->nick = keepAlive.second.mNick;
		event->signature = keepAlive.second.mSignature;
		event->PeerId(keepAlive.first);
		mChat->releasePresignedKeepAlive(event);
	}
}

void p3MobileLink::statusChange(const std::list<pqiServicePeer>& plist)
{
	statusChangeLocked(plist);
	updateSleepAllowed();

	for(const pqiServicePeer& peer: plist)
		if(peer.actions & RS_SERVICE_PEER_REMOVED)
		{
			IndicateConfigChanged();
			break;
		}
}

void p3MobileLink::statusChangeLocked(const std::list<pqiServicePeer>& plist)
{
	std::lock_guard<std::mutex> lock(mMtx);

	for(const pqiServicePeer& peer: plist)
	{
		if(peer.actions & RS_SERVICE_PEER_CONNECTED)
			mHomes[peer.id] = HomeState();

		if(peer.actions & (RS_SERVICE_PEER_DISCONNECTED | RS_SERVICE_PEER_REMOVED))
			mHomes.erase(peer.id);

		// A phone loses its connection whenever it changes network, or when
		// a network address translator forgets it. Its home keeps what it
		// knows of it meanwhile, so that a phone in background stays quiet
		// across the reconnection: until its STATE says otherwise, the home
		// sends it no heartbeat, no sync and none of the lobby traffic it
		// keeps for it.
		if(peer.actions & RS_SERVICE_PEER_REMOVED)
		{
			mPhones.erase(peer.id);
			mKnownHomes.erase(peer.id);
		}
	}
}

/******************************************************************************/
/*                                  Config                                    */
/******************************************************************************/

RsSerialiser* p3MobileLink::setupSerialiser()
{
	auto serialiser = new RsSerialiser();
	serialiser->addSerialType(new RsGeneralConfigSerialiser());
	return serialiser;
}

bool p3MobileLink::saveList(bool& cleanup, std::list<RsItem*>& lst)
{
	cleanup = true;

	auto set = new RsConfigKeyValueSet();
	RsTlvKeyValue kv;
	{
		std::lock_guard<std::mutex> lock(mMtx);

		kv.key = "PHONE_MODE";
		kv.value = mPhoneMode ? "TRUE" : "FALSE";
		set->tlvkvs.pairs.push_back(kv);

		kv.key = "SERVE_PHONES";
		kv.value = mServePhones ? "TRUE" : "FALSE";
		set->tlvkvs.pairs.push_back(kv);

		kv.key = "KEEP_ALIVE_INTERVAL";
		kv.value = std::to_string(mKeepAliveInterval);
		set->tlvkvs.pairs.push_back(kv);

		for(const RsPeerId& home: mKnownHomes)
		{
			kv.key = "HOME";
			kv.value = home.toStdString();
			set->tlvkvs.pairs.push_back(kv);
		}
	}
	lst.push_back(set);

	return true;
}

bool p3MobileLink::loadList(std::list<RsItem*>& load)
{
	for(RsItem* item: load)
	{
		if(auto set = dynamic_cast<RsConfigKeyValueSet*>(item))
		{
			std::lock_guard<std::mutex> lock(mMtx);

			for(const RsTlvKeyValue& kv: set->tlvkvs.pairs)
			{
				if(kv.key == "PHONE_MODE")
					mPhoneMode = (kv.value == "TRUE");
				else if(kv.key == "SERVE_PHONES")
					mServePhones = (kv.value != "FALSE");
				else if(kv.key == "KEEP_ALIVE_INTERVAL")
				{
					unsigned long seconds = std::strtoul(kv.value.c_str(), nullptr, 10);
					if(seconds > 0)
						mKeepAliveInterval = static_cast<uint32_t>(seconds);
				}
				else if(kv.key == "HOME")
				{
					RsPeerId home(kv.value);
					if(!home.isNull()) mKnownHomes.insert(home);
				}
			}
		}
		delete item;
	}
	load.clear();

	return true;
}
