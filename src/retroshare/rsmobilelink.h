/*******************************************************************************
 * libretroshare/src/retroshare: rsmobilelink.h                                *
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

#include <cstdint>
#include <map>
#include <vector>

#include "retroshare/rsids.h"
#include "serialiser/rsserializable.h"
#include "serialiser/rstypeserializer.h"
#include "util/rstime.h"

class RsMobileLink;

/**
 * Pointer to global instance of RsMobileLink service implementation
 * @jsonapi{development}
 */
extern RsMobileLink* rsMobileLink;

/// What a home knows of a phone among its friends.
struct RsMobileLinkPhoneInfo: RsSerializable
{
	RsPeerId mPeerId;

	/// Whether the phone is in background.
	bool mQuiet = false;

	/// Seconds between two keep-alives of the phone while quiet.
	uint32_t mKeepAliveInterval = 0;

	rstime_t mLastHello = 0;
	rstime_t mLastPing = 0;

	/// The phone's own GXS identities.
	std::vector<RsGxsId> mOwnIds;

	/// The identity the phone uses in each chat lobby it takes part in.
	std::map<uint64_t, RsGxsId> mLobbyIds;

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{
		RS_SERIAL_PROCESS(mPeerId);
		RS_SERIAL_PROCESS(mQuiet);
		RS_SERIAL_PROCESS(mKeepAliveInterval);
		RS_SERIAL_PROCESS(mLastHello);
		RS_SERIAL_PROCESS(mLastPing);
		RS_SERIAL_PROCESS(mOwnIds);
		RS_SERIAL_PROCESS(mLobbyIds);
	}
};

/// What a phone knows of a friend that can be its home.
struct RsMobileLinkHomeInfo: RsSerializable
{
	RsPeerId mPeerId;

	/// Whether that friend accepted to serve this phone.
	bool mServing = false;

	/// When it last answered a keep-alive.
	rstime_t mLastPong = 0;

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{
		RS_SERIAL_PROCESS(mPeerId);
		RS_SERIAL_PROCESS(mServing);
		RS_SERIAL_PROCESS(mLastPong);
	}
};

/**
 * MobileLink lets a phone ask a friend that stays in the network, its home, to
 * spare its battery and its data: the home sends it only the tunnel requests
 * for its own identities, and no search request. The home never gets any key
 * of the phone. Both run this service; a friend that does not run it sees no
 * change.
 */
class RsMobileLink
{
public:
	virtual ~RsMobileLink();

	/**
	 * @brief Set whether this node is a phone. A phone tells the friends that
	 *  run MobileLink who it is, so that they spare it. Saved.
	 * @jsonapi{development}
	 * @param[in] phone true on a phone
	 */
	virtual void setPhoneMode(bool phone) = 0;

	/**
	 * @brief Whether this node is a phone
	 * @jsonapi{development}
	 * @return true on a phone
	 */
	virtual bool getPhoneMode() = 0;

	/**
	 * @brief Set whether the phone is in background. The app sets it when it
	 *  leaves the foreground and when it comes back. Not saved: a phone starts
	 *  in foreground.
	 * @jsonapi{development}
	 * @param[in] quiet true in background
	 */
	virtual void setQuiet(bool quiet) = 0;

	/**
	 * @brief Whether the phone is in background
	 * @jsonapi{development}
	 * @return true in background
	 */
	virtual bool getQuiet() = 0;

	/**
	 * @brief Set how often the phone sends a keep-alive while in background,
	 *  so that the network address translators on the way keep its connection
	 *  open. The phone's alarm calls keepAliveNow() at that interval. Saved.
	 * @jsonapi{development}
	 * @param[in] seconds interval in seconds
	 */
	virtual void setKeepAliveInterval(uint32_t seconds) = 0;

	/**
	 * @brief The keep-alive interval
	 * @jsonapi{development}
	 * @return interval in seconds
	 */
	virtual uint32_t getKeepAliveInterval() = 0;

	/**
	 * @brief Send a keep-alive to the homes and wait for one of them to answer
	 * @jsonapi{development}
	 * @param[in] timeoutSeconds how long to wait for an answer
	 * @return true if a home answered in time
	 */
	virtual bool keepAliveNow(uint32_t timeoutSeconds) = 0;

	/**
	 * @brief The connected friends that run MobileLink, seen from a phone
	 * @jsonapi{development}
	 * @param[out] homes one entry per friend
	 */
	virtual void getHomes(std::vector<RsMobileLinkHomeInfo>& homes) = 0;

	/**
	 * @brief Set whether this node spares the phones among its friends. On by
	 *  default. Saved.
	 * @jsonapi{development}
	 * @param[in] serve false to treat phones as any other friend
	 */
	virtual void setServePhones(bool serve) = 0;

	/**
	 * @brief Whether this node spares the phones among its friends
	 * @jsonapi{development}
	 * @return true when it does
	 */
	virtual bool getServePhones() = 0;

	/**
	 * @brief The phones among the friends, including those that lost their
	 *  connection less than a day ago
	 * @jsonapi{development}
	 * @param[out] phones one entry per phone
	 */
	virtual void getPhones(std::vector<RsMobileLinkPhoneInfo>& phones) = 0;
};
