/*******************************************************************************
 * libretroshare/src/rsitems: rsmobilepushitems.h                              *
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

#include "retroshare/rsmobilepush.h"
#include "rsitems/itempriorities.h"
#include "rsitems/rsitem.h"
#include "rsitems/rsserviceids.h"
#include "serialiser/rsserializer.h"
#include "serialiser/rstypeserializer.h"

// Items of the MobilePush service. See services/p3mobilepush.h.

const uint8_t RS_PKT_SUBTYPE_MOBILE_PUSH_REGISTRATION = 0x01;

/// Phone to home: how to push to the phone. Sent at each connection and when
/// it changes; an empty token withdraws it.
class RsMobilePushRegistrationItem: public RsItem
{
public:
	RsMobilePushRegistrationItem():
	    RsItem( RS_PKT_VERSION_SERVICE,
	            static_cast<uint16_t>(RsServiceType::MOBILE_PUSH),
	            RS_PKT_SUBTYPE_MOBILE_PUSH_REGISTRATION )
	{ setPriorityLevel(QOS_PRIORITY_RS_HEARTBEAT_PULSE); }

	void serial_process( RsGenericSerializer::SerializeJob j,
	                     RsGenericSerializer::SerializeContext& ctx ) override
	{ RS_SERIAL_PROCESS(mRegistration); }

	void clear() override { mRegistration = RsMobilePushRegistration(); }

	RsMobilePushRegistration mRegistration;
};

class RsMobilePushSerialiser: public RsServiceSerializer
{
public:
	RsMobilePushSerialiser():
	    RsServiceSerializer(static_cast<uint16_t>(RsServiceType::MOBILE_PUSH)) {}

	RsItem* create_item(uint16_t service, uint8_t subtype) const override;
};
