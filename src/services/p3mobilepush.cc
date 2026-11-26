/*******************************************************************************
 * libretroshare/src/services: p3mobilepush.cc                                 *
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
#include "services/p3mobilepush.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "chat/rschatitems.h"
#include "crypto/chacha20.h"
#include "pqi/p3servicecontrol.h"
#include "retroshare/rsidentity.h"
#include "retroshare/rsmobilelink.h"
#include "rsitems/rsconfigitems.h"
#include "services/p3mobilelink.h"
#include "util/radix64.h"
#include "util/rsdebug.h"
#include "util/rsrandom.h"

RsMobilePush* rsMobilePush = nullptr;

RsMobilePush::~RsMobilePush() = default;

static const size_t PUSH_KEY_SIZE = 32;
static const size_t PUSH_NONCE_SIZE = 12;
static const size_t PUSH_TAG_SIZE = 16;

/// The longest text put in a notification, in bytes. The push services take
/// a few kilobytes in all, sealing and base64 included.
static const size_t MAX_NOTIFICATION_TEXT = 1000;

/// A home keeps at most this many notifications, for all its phones.
static const size_t MAX_QUEUED_NOTIFICATIONS = 500;

/// A notification nobody delivered for this long is dropped.
static const rstime_t MAX_NOTIFICATION_AGE = 86400;

/// A phone gets at most this many notifications in a row, then one more for
/// each period that passes. The lines beyond that are still kept for the
/// phone by the chat service: it gets them when it comes back.
static const double PUSH_BURST = 5;
static const rstime_t PUSH_PERIOD = 20;

static const std::string MOBILE_PUSH_APP_NAME = "mobilepush";
static const uint16_t MOBILE_PUSH_APP_MAJOR_VERSION = 1;
static const uint16_t MOBILE_PUSH_APP_MINOR_VERSION = 0;
static const uint16_t MOBILE_PUSH_MIN_MAJOR_VERSION = 1;
static const uint16_t MOBILE_PUSH_MIN_MINOR_VERSION = 0;

static bool validMode(unsigned long value)
{ return value <= static_cast<unsigned long>(RsMobilePushLobbyMode::NONE); }

static bool validKey(const std::string& base64)
{ return Radix64::decode(base64).size() == PUSH_KEY_SIZE; }

/// The text of a chat line as a notification shows it: the desktop sends
/// rich text.
static std::string plainText(const std::string& html)
{
	std::string text;
	text.reserve(html.size());

	for(size_t i = 0; i < html.size();)
	{
		if(html[i] == '<')
		{
			// The style sheet of a rich text document is not text.
			if(html.compare(i, 6, "<style") == 0)
			{
				size_t end = html.find("</style>", i);
				if(end == std::string::npos) break;
				i = end + 8;
				continue;
			}
			size_t end = html.find('>', i);
			if(end == std::string::npos) break;
			if(html.compare(i, 3, "<br") == 0 || html.compare(i, 3, "</p") == 0)
				text += ' ';
			i = end + 1;
		}
		else if(html[i] == '&')
		{
			static const struct { const char* entity; const char* text; } entities[] = {
				{ "&amp;", "&" }, { "&lt;", "<" }, { "&gt;", ">" },
				{ "&quot;", "\"" }, { "&apos;", "'" }, { "&#39;", "'" },
				{ "&nbsp;", " " } };
			bool found = false;
			for(const auto& e: entities)
				if(html.compare(i, strlen(e.entity), e.entity) == 0)
				{
					text += e.text;
					i += strlen(e.entity);
					found = true;
					break;
				}
			if(!found) text += html[i++];
		}
		else
			text += html[i++];
	}

	// One space for any run of white space, none at the ends.
	std::string out;
	bool space = false;
	for(unsigned char c: text)
		if(c == ' ' || c == '\n' || c == '\r' || c == '\t')
			space = !out.empty();
		else
		{
			if(space) out += ' ';
			space = false;
			out += static_cast<char>(c);
		}

	if(out.size() > MAX_NOTIFICATION_TEXT)
	{
		// Cut between two UTF-8 characters.
		size_t cut = MAX_NOTIFICATION_TEXT;
		while(cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xC0) == 0x80) --cut;
		out.resize(cut);
		out += "\xE2\x80\xA6";
	}
	return out;
}

/// Seals clear with key: base64 of nonce, ciphertext and tag. Empty on error.
static std::string seal(const std::string& clear, const std::string& keyBase64)
{
	std::vector<uint8_t> key(Radix64::decode(keyBase64));
	if(key.size() != PUSH_KEY_SIZE) return std::string();

	std::vector<uint8_t> box(PUSH_NONCE_SIZE + clear.size() + PUSH_TAG_SIZE);
	RsRandom::random_bytes(box.data(), PUSH_NONCE_SIZE);
	memcpy(box.data() + PUSH_NONCE_SIZE, clear.data(), clear.size());

	if(!librs::crypto::AEAD_chacha20_poly1305(
	            key.data(), box.data(), box.data() + PUSH_NONCE_SIZE,
	            static_cast<uint32_t>(clear.size()), nullptr, 0,
	            box.data() + PUSH_NONCE_SIZE + clear.size(), true ))
		return std::string();

	std::string base64;
	Radix64::encode(box.data(), box.size(), base64);
	return base64;
}

p3MobilePush::p3MobilePush( p3ServiceControl* serviceControl,
                            p3MobileLink* mobileLink ):
    mServiceControl(serviceControl), mMobileLink(mobileLink)
{
	addSerialType(new RsMobilePushSerialiser());
}

RsServiceInfo p3MobilePush::getServiceInfo()
{
	return RsServiceInfo( static_cast<uint16_t>(RsServiceType::MOBILE_PUSH),
	                      MOBILE_PUSH_APP_NAME,
	                      MOBILE_PUSH_APP_MAJOR_VERSION,
	                      MOBILE_PUSH_APP_MINOR_VERSION,
	                      MOBILE_PUSH_MIN_MAJOR_VERSION,
	                      MOBILE_PUSH_MIN_MINOR_VERSION );
}

/******************************************************************************/
/*                               RsMobilePush                                 */
/******************************************************************************/

bool p3MobilePush::setRegistration(const RsMobilePushRegistration& registration)
{
	if(!registration.mToken.empty() && !validKey(registration.mKey))
		return false;

	{
		std::lock_guard<std::mutex> lock(mMtx);
		mRegistration = registration;

		std::set<RsPeerId> connected;
		mServiceControl->getPeersConnected(getServiceInfo().mServiceType, connected);
		mToRegisterWith = connected;
	}
	IndicateConfigChanged();
	return true;
}

void p3MobilePush::getRegistration(RsMobilePushRegistration& registration)
{
	std::lock_guard<std::mutex> lock(mMtx);
	registration = mRegistration;
}

void p3MobilePush::getRegisteredPhones(std::vector<RsPeerId>& phones)
{
	std::lock_guard<std::mutex> lock(mMtx);
	phones.clear();
	for(const auto& phone: mPhones) phones.push_back(phone.first);
}

void p3MobilePush::getPendingNotifications(
        std::vector<RsMobilePushNotification>& notifications )
{
	std::lock_guard<std::mutex> lock(mMtx);
	notifications.assign(mQueue.begin(), mQueue.end());
}

void p3MobilePush::acknowledgeNotifications(const std::vector<uint32_t>& ids)
{
	std::lock_guard<std::mutex> lock(mMtx);
	mQueue.remove_if( [&ids](const RsMobilePushNotification& n)
	{ return std::find(ids.begin(), ids.end(), n.mId) != ids.end(); } );
}

void p3MobilePush::setLobbyMode(uint64_t lobbyId, RsMobilePushLobbyMode mode)
{
	if(!validMode(static_cast<unsigned long>(mode))) return;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		mLobbyModes[lobbyId] = mode;
	}
	IndicateConfigChanged();
}

void p3MobilePush::getLobbyModes(
        std::map<uint64_t, RsMobilePushLobbyMode>& modes )
{
	std::lock_guard<std::mutex> lock(mMtx);
	modes = mLobbyModes;
}

void p3MobilePush::setDefaultLobbyMode(RsMobilePushLobbyMode mode)
{
	if(!validMode(static_cast<unsigned long>(mode))) return;
	{
		std::lock_guard<std::mutex> lock(mMtx);
		mDefaultLobbyMode = mode;
	}
	IndicateConfigChanged();
}

RsMobilePushLobbyMode p3MobilePush::getDefaultLobbyMode()
{
	std::lock_guard<std::mutex> lock(mMtx);
	return mDefaultLobbyMode;
}

/******************************************************************************/
/*                                Home side                                   */
/******************************************************************************/

void p3MobilePush::lineHeldForPhone( const RsPeerId& phone, uint64_t lobby,
                                     const std::string& lobbyName,
                                     const RsChatLobbyMsgItem& line )
{
	std::lock_guard<std::mutex> lock(mMtx);

	auto it = mPhones.find(phone);
	if(it == mPhones.end()) return;
	PhoneState& state(it->second);

	auto modeIt = mLobbyModes.find(lobby);
	switch(modeIt != mLobbyModes.end() ? modeIt->second : mDefaultLobbyMode)
	{
	case RsMobilePushLobbyMode::ALL: break;
	case RsMobilePushLobbyMode::OWN_LINES:
		if(!rsIdentity || !rsIdentity->isOwnId(line.signature.keyId)) return;
		break;
	case RsMobilePushLobbyMode::NONE: return;
	}

	rstime_t now = time(nullptr);
	state.mAllowance = std::min( PUSH_BURST, state.mAllowance +
	        static_cast<double>(now - state.mAllowanceTime) / PUSH_PERIOD );
	state.mAllowanceTime = now;
	if(state.mAllowance < 1) return;

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	writer.StartObject();
	writer.Key("title");  writer.String(lobbyName.c_str());
	writer.Key("from");   writer.String(line.nick.c_str());
	writer.Key("text");   writer.String(plainText(line.message).c_str());
	writer.Key("thread"); writer.String(std::to_string(lobby).c_str());
	writer.EndObject();

	RsMobilePushNotification notification;
	notification.mPayload = seal(
	            std::string(buffer.GetString(), buffer.GetSize()),
	            state.mRegistration.mKey );
	if(notification.mPayload.empty()) return;

	state.mAllowance -= 1;

	notification.mId = mNextId++;
	notification.mPhone = phone;
	notification.mProvider = state.mRegistration.mProvider;
	notification.mToken = state.mRegistration.mToken;
	notification.mTopic = state.mRegistration.mTopic;
	notification.mCreated = now;

	mQueue.push_back(notification);
	while(mQueue.size() > MAX_QUEUED_NOTIFICATIONS) mQueue.pop_front();
}

void p3MobilePush::handleRegistration(
        const RsPeerId& peer, const RsMobilePushRegistration& registration )
{
	// Only a friend MobileLink knows as a phone registers.
	std::vector<RsMobileLinkPhoneInfo> phones;
	mMobileLink->getPhones(phones);
	if(std::none_of( phones.begin(), phones.end(),
	                 [&peer](const RsMobileLinkPhoneInfo& p)
	                 { return p.mPeerId == peer; } ))
	{
		RS_WARN("registration from ", peer, " which is not a phone: ignored");
		return;
	}

	{
		std::lock_guard<std::mutex> lock(mMtx);

		if(registration.mToken.empty())
			mPhones.erase(peer);
		else if(validKey(registration.mKey))
		{
			PhoneState& state(mPhones[peer]);
			state.mRegistration = registration;
			state.mAllowance = PUSH_BURST;
			state.mAllowanceTime = time(nullptr);
		}
		else
			return;
	}
	RS_INFO( "phone ", peer, registration.mToken.empty() ?
	             " withdrew its push registration" :
	             " registered for push (" + registration.mProvider + ")" );
	IndicateConfigChanged();
}

/******************************************************************************/
/*                                Phone side                                  */
/******************************************************************************/

void p3MobilePush::sendRegistrationToHomes()
{
	std::list<RsMobilePushRegistrationItem*> toSend;
	{
		std::lock_guard<std::mutex> lock(mMtx);

		// Nothing to tell a home that never had a registration.
		if(mRegistration.mKey.empty())
		{
			mToRegisterWith.clear();
			return;
		}

		for(auto it = mToRegisterWith.begin(); it != mToRegisterWith.end();)
			if(mMobileLink->isHome(*it))
			{
				auto item = new RsMobilePushRegistrationItem();
				item->PeerId(*it);
				item->mRegistration = mRegistration;
				toSend.push_back(item);
				it = mToRegisterWith.erase(it);
			}
			else
				++it;
	}
	for(auto item: toSend) sendItem(item);
}

/******************************************************************************/
/*                               p3FastService                                */
/******************************************************************************/

int p3MobilePush::tick()
{
	rstime_t now = time(nullptr);
	{
		std::lock_guard<std::mutex> lock(mMtx);
		if(now == mLastTick) return 0;
		mLastTick = now;

		while(!mQueue.empty() && mQueue.front().mCreated + MAX_NOTIFICATION_AGE < now)
			mQueue.pop_front();
	}
	sendRegistrationToHomes();
	return 0;
}

bool p3MobilePush::recvItem(RsItem* item)
{
	if(auto registration = dynamic_cast<RsMobilePushRegistrationItem*>(item))
		handleRegistration(item->PeerId(), registration->mRegistration);

	delete item;
	return true;
}

void p3MobilePush::statusChange(const std::list<pqiServicePeer>& plist)
{
	bool removed = false;
	{
		std::lock_guard<std::mutex> lock(mMtx);

		for(const pqiServicePeer& peer: plist)
		{
			if(peer.actions & RS_SERVICE_PEER_CONNECTED)
				mToRegisterWith.insert(peer.id);

			if(peer.actions & (RS_SERVICE_PEER_DISCONNECTED | RS_SERVICE_PEER_REMOVED))
				mToRegisterWith.erase(peer.id);

			if((peer.actions & RS_SERVICE_PEER_REMOVED) && mPhones.erase(peer.id))
				removed = true;
		}
	}
	if(removed) IndicateConfigChanged();
}

/******************************************************************************/
/*                                  Config                                    */
/******************************************************************************/

RsSerialiser* p3MobilePush::setupSerialiser()
{
	auto serialiser = new RsSerialiser();
	serialiser->addSerialType(new RsGeneralConfigSerialiser());
	return serialiser;
}

/// A registration as one configuration value: its four fields, none of which
/// holds a line break.
static std::string registrationToString(const RsMobilePushRegistration& r)
{ return r.mProvider + "\n" + r.mToken + "\n" + r.mTopic + "\n" + r.mKey; }

static bool registrationFromString( const std::string& s,
                                    RsMobilePushRegistration& r )
{
	size_t a = s.find('\n');
	size_t b = a == std::string::npos ? a : s.find('\n', a + 1);
	size_t c = b == std::string::npos ? b : s.find('\n', b + 1);
	if(c == std::string::npos) return false;

	r.mProvider = s.substr(0, a);
	r.mToken = s.substr(a + 1, b - a - 1);
	r.mTopic = s.substr(b + 1, c - b - 1);
	r.mKey = s.substr(c + 1);
	return validKey(r.mKey);
}

bool p3MobilePush::saveList(bool& cleanup, std::list<RsItem*>& lst)
{
	cleanup = true;

	auto set = new RsConfigKeyValueSet();
	RsTlvKeyValue kv;
	{
		std::lock_guard<std::mutex> lock(mMtx);

		if(!mRegistration.mKey.empty())
		{
			kv.key = "REGISTRATION";
			kv.value = registrationToString(mRegistration);
			set->tlvkvs.pairs.push_back(kv);
		}

		for(const auto& phone: mPhones)
		{
			kv.key = "PHONE " + phone.first.toStdString();
			kv.value = registrationToString(phone.second.mRegistration);
			set->tlvkvs.pairs.push_back(kv);
		}

		kv.key = "DEFAULT_LOBBY_MODE";
		kv.value = std::to_string(static_cast<unsigned>(mDefaultLobbyMode));
		set->tlvkvs.pairs.push_back(kv);

		for(const auto& lobby: mLobbyModes)
		{
			kv.key = "LOBBY_MODE " + std::to_string(lobby.first);
			kv.value = std::to_string(static_cast<unsigned>(lobby.second));
			set->tlvkvs.pairs.push_back(kv);
		}
	}
	lst.push_back(set);

	return true;
}

bool p3MobilePush::loadList(std::list<RsItem*>& load)
{
	for(RsItem* item: load)
	{
		if(auto set = dynamic_cast<RsConfigKeyValueSet*>(item))
		{
			std::lock_guard<std::mutex> lock(mMtx);

			for(const RsTlvKeyValue& kv: set->tlvkvs.pairs)
			{
				if( kv.key == "DEFAULT_LOBBY_MODE" ||
				        kv.key.compare(0, 11, "LOBBY_MODE ") == 0 )
				{
					unsigned long mode = std::strtoul(kv.value.c_str(), nullptr, 10);
					if(!validMode(mode)) continue;

					if(kv.key == "DEFAULT_LOBBY_MODE")
						mDefaultLobbyMode = static_cast<RsMobilePushLobbyMode>(mode);
					else
						mLobbyModes[std::strtoull(kv.key.c_str() + 11, nullptr, 10)] =
						        static_cast<RsMobilePushLobbyMode>(mode);
					continue;
				}

				RsMobilePushRegistration registration;
				if(!registrationFromString(kv.value, registration))
					continue;

				if(kv.key == "REGISTRATION")
					mRegistration = registration;
				else if(kv.key.compare(0, 6, "PHONE ") == 0)
				{
					RsPeerId phone(kv.key.substr(6));
					if(phone.isNull()) continue;

					PhoneState& state(mPhones[phone]);
					state.mRegistration = registration;
					state.mAllowance = PUSH_BURST;
					state.mAllowanceTime = time(nullptr);
				}
			}
		}
		delete item;
	}
	load.clear();

	return true;
}
