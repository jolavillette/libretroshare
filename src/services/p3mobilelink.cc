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
#include <string>

#include "grouter/groutertypes.h"
#include "grouter/p3grouter.h"
#include "gxstunnel/p3gxstunnel.h"
#include "pqi/p3servicecontrol.h"
#include "retroshare/rschats.h"
#include "retroshare/rsidentity.h"
#include "rsitems/rsconfigitems.h"
#include "util/rsdebug.h"

RsMobileLink* rsMobileLink = nullptr;

RsMobileLink::~RsMobileLink() = default;

/// How often a phone looks whether its identities or lobbies changed.
static const rstime_t IDENTITY_CHECK_PERIOD = 60;

/// A phone's keep-alive interval by default. Mobile networks forget an idle
/// connection after a few minutes; the app adjusts it to the network.
static const uint32_t DEFAULT_KEEP_ALIVE_INTERVAL = 240;

/// The silence a phone in background and its home accept from each other:
/// three keep-alive intervals, and never less than this.
static const rstime_t MIN_SILENCE_TOLERANCE = 900;

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
		for(const auto& home: mHomes) homes.push_back(home.first);
	}
	RsInfo() << "MobileLink: " << (quiet ? "quiet" : "active");

	for(const RsPeerId& home: homes) sendState(home);
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

bool p3MobileLink::keepAliveNow(uint32_t timeoutSeconds)
{
	std::vector<RsPeerId> homes;
	uint32_t seq;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		for(const auto& home: mHomes) homes.push_back(home.first);
		seq = ++mPingSeq;
	}
	if(homes.empty()) return false;

	for(const RsPeerId& home: homes)
	{
		auto ping = new RsMobileLinkPingItem();
		ping->PeerId(home);
		ping->mSeq = seq;
		sendItem(ping);
	}

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

	// Home side: a phone in background.
	auto phone = mPhones.find(peer);
	if(phone != mPhones.end() && phone->second.mQuiet)
		return silenceToleranceFor(phone->second.mKeepAliveInterval);

	// Phone side: its homes while it is in background.
	if(mPhoneMode && mQuiet && mHomes.count(peer))
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

bool p3MobileLink::wantsHeartbeat(const RsPeerId& peer)
{
	std::lock_guard<std::mutex> lock(mMtx);

	auto phone = mPhones.find(peer);
	if(phone != mPhones.end() && phone->second.mQuiet) return false;

	return !(mPhoneMode && mQuiet && mHomes.count(peer));
}

/******************************************************************************/
/*                                  Items                                     */
/******************************************************************************/

int p3MobileLink::tick()
{
	checkOwnIdentities();

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
	}

	return 0;
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
	std::lock_guard<std::mutex> lock(mMtx);

	auto it = mHomes.find(item.PeerId());
	if(it != mHomes.end()) it->second.mServing = item.mServing;
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

	it->second.mQuiet = item.mQuiet;
	it->second.mKeepAliveInterval = item.mKeepAliveInterval;
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

void p3MobileLink::statusChange(const std::list<pqiServicePeer>& plist)
{
	std::lock_guard<std::mutex> lock(mMtx);

	for(const pqiServicePeer& peer: plist)
	{
		if(peer.actions & RS_SERVICE_PEER_CONNECTED)
			mHomes[peer.id] = HomeState();

		if(peer.actions & (RS_SERVICE_PEER_DISCONNECTED | RS_SERVICE_PEER_REMOVED))
		{
			mHomes.erase(peer.id);
			mPhones.erase(peer.id);
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
			}
		}
		delete item;
	}
	load.clear();

	return true;
}
