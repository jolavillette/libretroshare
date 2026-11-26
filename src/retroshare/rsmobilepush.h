/*******************************************************************************
 * libretroshare/src/retroshare: rsmobilepush.h                                *
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
#include <string>
#include <vector>

#include "retroshare/rsids.h"
#include "serialiser/rsserializable.h"
#include "serialiser/rstypeserializer.h"
#include "util/rstime.h"

class RsMobilePush;

/**
 * Pointer to global instance of RsMobilePush service implementation
 * @jsonapi{development}
 */
extern RsMobilePush* rsMobilePush;

/// What a phone gives its homes so that they can reach it through the push
/// service of its platform while the application is not running.
struct RsMobilePushRegistration: RsSerializable
{
	/// The push service: "apns" for Apple's.
	std::string mProvider;

	/// The address the push service gave this installation.
	std::string mToken;

	/// The application the token belongs to (its bundle identifier for Apple).
	std::string mTopic;

	/// 32 random bytes in base64. The homes seal the notifications with it,
	/// so that the push service carries text it cannot read.
	std::string mKey;

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{
		RS_SERIAL_PROCESS(mProvider);
		RS_SERIAL_PROCESS(mToken);
		RS_SERIAL_PROCESS(mTopic);
		RS_SERIAL_PROCESS(mKey);
	}
};

/// A notification a home has for a phone, to be handed to the push service.
struct RsMobilePushNotification: RsSerializable
{
	uint32_t mId = 0;
	RsPeerId mPhone;
	std::string mProvider;
	std::string mToken;
	std::string mTopic;

	/// The sealed message in base64: a ChaCha20-Poly1305 box (12-byte nonce,
	/// ciphertext, 16-byte tag) around a JSON object with the fields "title",
	/// "from", "text" and "thread".
	std::string mPayload;

	rstime_t mCreated = 0;

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{
		RS_SERIAL_PROCESS(mId);
		RS_SERIAL_PROCESS(mPhone);
		RS_SERIAL_PROCESS(mProvider);
		RS_SERIAL_PROCESS(mToken);
		RS_SERIAL_PROCESS(mTopic);
		RS_SERIAL_PROCESS(mPayload);
		RS_SERIAL_PROCESS(mCreated);
	}
};

/**
 * Push notifications for phones, on top of MobileLink.
 *
 * A phone registers with its homes. A home that keeps a chat lobby line for a
 * phone also queues a sealed notification for it. libretroshare does not talk
 * to the push services: a separate sender reads the queue through this
 * interface, delivers and acknowledges.
 */
class RsMobilePush
{
public:
	virtual ~RsMobilePush();

	/**
	 * @brief Phone side: set what the homes need to push to this phone. Sent
	 *  to each home at connection and when it changes. Saved.
	 * @jsonapi{development}
	 * @param[in] registration push service, token, topic and key; an empty
	 *  token withdraws the registration
	 * @return false if the key is not 32 bytes in base64
	 */
	virtual bool setRegistration(const RsMobilePushRegistration& registration) = 0;

	/**
	 * @brief Phone side: the registration given to the homes
	 * @jsonapi{development}
	 * @param[out] registration empty fields when none was set
	 */
	virtual void getRegistration(RsMobilePushRegistration& registration) = 0;

	/**
	 * @brief Home side: the phones that registered for push
	 * @jsonapi{development}
	 * @param[out] phones their peer ids
	 */
	virtual void getRegisteredPhones(std::vector<RsPeerId>& phones) = 0;

	/**
	 * @brief Home side: the notifications waiting to be delivered, oldest
	 *  first. They stay until acknowledged or one day old.
	 * @jsonapi{development}
	 * @param[out] notifications the queue
	 */
	virtual void getPendingNotifications(
	        std::vector<RsMobilePushNotification>& notifications ) = 0;

	/**
	 * @brief Home side: remove delivered notifications from the queue
	 * @jsonapi{development}
	 * @param[in] ids their mId
	 */
	virtual void acknowledgeNotifications(const std::vector<uint32_t>& ids) = 0;
};
