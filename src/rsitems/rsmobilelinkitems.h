/*******************************************************************************
 * libretroshare/src/rsitems: rsmobilelinkitems.h                              *
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
#include "rsitems/itempriorities.h"
#include "rsitems/rsitem.h"
#include "rsitems/rsserviceids.h"
#include "serialiser/rsserializer.h"
#include "serialiser/rstlvkeys.h"
#include "serialiser/rstypeserializer.h"

// Items of the MobileLink service, between a phone and its home: the friend
// that stays in the network for it. See services/p3mobilelink.h.

const uint8_t RS_PKT_SUBTYPE_MOBILE_LINK_HELLO = 0x01;
const uint8_t RS_PKT_SUBTYPE_MOBILE_LINK_HOME  = 0x02;
const uint8_t RS_PKT_SUBTYPE_MOBILE_LINK_STATE = 0x03;
const uint8_t RS_PKT_SUBTYPE_MOBILE_LINK_PING  = 0x04;
const uint8_t RS_PKT_SUBTYPE_MOBILE_LINK_PONG  = 0x05;
const uint8_t RS_PKT_SUBTYPE_MOBILE_LINK_KEEP_ALIVE_STOCK = 0x06;
const uint8_t RS_PKT_SUBTYPE_MOBILE_LINK_HELD_END = 0x07;
const uint8_t RS_PKT_SUBTYPE_MOBILE_LINK_HELD_ACK = 0x08;
const uint8_t RS_PKT_SUBTYPE_MOBILE_LINK_FILES = 0x09;

class RsMobileLinkItem: public RsItem
{
public:
	explicit RsMobileLinkItem(uint8_t subtype)
	    : RsItem( RS_PKT_VERSION_SERVICE,
	              static_cast<uint16_t>(RsServiceType::MOBILE_LINK), subtype )
	{ setPriorityLevel(QOS_PRIORITY_RS_HEARTBEAT_PULSE); }

	void clear() override {}
};

/// Phone to home: the phone's identities, so that the home knows which tunnel
/// requests are for it. Sent at each connection and when they change.
class RsMobileLinkHelloItem: public RsMobileLinkItem
{
public:
	RsMobileLinkHelloItem(): RsMobileLinkItem(RS_PKT_SUBTYPE_MOBILE_LINK_HELLO) {}

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{
		RS_SERIAL_PROCESS(mOwnIds);
		RS_SERIAL_PROCESS(mLobbyIds);
	}

	void clear() override { mOwnIds.clear(); mLobbyIds.clear(); }

	/// The phone's own GXS identities.
	std::vector<RsGxsId> mOwnIds;

	/// The identity the phone uses in each chat lobby it takes part in.
	std::map<uint64_t, RsGxsId> mLobbyIds;
};

/// Home to phone: whether the home serves phones, in answer to a HELLO.
class RsMobileLinkHomeItem: public RsMobileLinkItem
{
public:
	RsMobileLinkHomeItem(): RsMobileLinkItem(RS_PKT_SUBTYPE_MOBILE_LINK_HOME) {}

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{ RS_SERIAL_PROCESS(mServing); }

	bool mServing = false;
};

/// Phone to home: whether the node is a phone, whether it is quiet (in
/// background), and how often it sends a keep-alive while quiet.
class RsMobileLinkStateItem: public RsMobileLinkItem
{
public:
	RsMobileLinkStateItem(): RsMobileLinkItem(RS_PKT_SUBTYPE_MOBILE_LINK_STATE) {}

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{
		RS_SERIAL_PROCESS(mPhone);
		RS_SERIAL_PROCESS(mQuiet);
		RS_SERIAL_PROCESS(mKeepAliveInterval);
	}

	bool mPhone = false;
	bool mQuiet = false;

	/// Seconds.
	uint32_t mKeepAliveInterval = 0;
};

/// Phone to home: the keep-alive. The home answers with a PONG of the same
/// sequence number.
class RsMobileLinkPingItem: public RsMobileLinkItem
{
public:
	RsMobileLinkPingItem(): RsMobileLinkItem(RS_PKT_SUBTYPE_MOBILE_LINK_PING) {}

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{ RS_SERIAL_PROCESS(mSeq); }

	uint32_t mSeq = 0;
};

class RsMobileLinkPongItem: public RsMobileLinkItem
{
public:
	RsMobileLinkPongItem(): RsMobileLinkItem(RS_PKT_SUBTYPE_MOBILE_LINK_PONG) {}

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{ RS_SERIAL_PROCESS(mSeq); }

	uint32_t mSeq = 0;
};

/// A chat lobby keep-alive a phone signed in advance: the fields of its
/// RsChatLobbyEventItem, for its home to send at mSendTime.
struct RsMobileLinkKeepAlive: RsSerializable
{
	uint64_t mLobbyId = 0;
	uint64_t mMsgId = 0;
	std::string mNick;
	uint32_t mSendTime = 0;
	RsTlvKeySignature mSignature;

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{
		RS_SERIAL_PROCESS(mLobbyId);
		RS_SERIAL_PROCESS(mMsgId);
		RS_SERIAL_PROCESS(mNick);
		RS_SERIAL_PROCESS(mSendTime);
		RS_SERIAL_PROCESS(mSignature);
	}
};

/// Phone to home: lobby keep-alives signed in advance. While the phone is in
/// background, its home sends each one at its time, so that the phone stays
/// in the lobbies' participant lists.
class RsMobileLinkKeepAliveStockItem: public RsMobileLinkItem
{
public:
	RsMobileLinkKeepAliveStockItem():
	    RsMobileLinkItem(RS_PKT_SUBTYPE_MOBILE_LINK_KEEP_ALIVE_STOCK) {}

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{ RS_SERIAL_PROCESS(mKeepAlives); }

	void clear() override { mKeepAlives.clear(); }

	std::vector<RsMobileLinkKeepAlive> mKeepAlives;
};

/// Home to phone: sent right after the lobby lines the home kept for the
/// phone, at the priority of chat items so that it leaves after them. The
/// phone answers with a HELD_ACK of the same batch number.
class RsMobileLinkHeldEndItem: public RsMobileLinkItem
{
public:
	RsMobileLinkHeldEndItem(): RsMobileLinkItem(RS_PKT_SUBTYPE_MOBILE_LINK_HELD_END)
	{ setPriorityLevel(QOS_PRIORITY_RS_CHAT_ITEM); }

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{ RS_SERIAL_PROCESS(mBatch); }

	uint32_t mBatch = 0;
};

/// Phone to home: the lines of batch mBatch arrived, the home may forget
/// them. With batch 0, sent after each HELLO: the phone acknowledges the
/// lines kept for it, so the home keeps them until it does.
class RsMobileLinkHeldAckItem: public RsMobileLinkItem
{
public:
	RsMobileLinkHeldAckItem(): RsMobileLinkItem(RS_PKT_SUBTYPE_MOBILE_LINK_HELD_ACK) {}

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{ RS_SERIAL_PROCESS(mBatch); }

	uint32_t mBatch = 0;
};

/// Phone to home: the tunnel hashes of the files the phone offers, the
/// attachments it posted. Its home lets the tunnel requests for them reach
/// it. Sent after each HELLO and when the list changes.
class RsMobileLinkFilesItem: public RsMobileLinkItem
{
public:
	RsMobileLinkFilesItem(): RsMobileLinkItem(RS_PKT_SUBTYPE_MOBILE_LINK_FILES) {}

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{ RS_SERIAL_PROCESS(mHashes); }

	void clear() override { mHashes.clear(); }

	std::vector<RsFileHash> mHashes;
};

class RsMobileLinkSerialiser: public RsServiceSerializer
{
public:
	RsMobileLinkSerialiser():
	    RsServiceSerializer(static_cast<uint16_t>(RsServiceType::MOBILE_LINK)) {}

	RsItem* create_item(uint16_t service, uint8_t subtype) const override;
};
