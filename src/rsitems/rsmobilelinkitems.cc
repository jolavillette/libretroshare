/*******************************************************************************
 * libretroshare/src/rsitems: rsmobilelinkitems.cc                             *
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
#include "rsitems/rsmobilelinkitems.h"

RsItem* RsMobileLinkSerialiser::create_item(uint16_t service, uint8_t subtype) const
{
	if(service != static_cast<uint16_t>(RsServiceType::MOBILE_LINK))
		return nullptr;

	switch(subtype)
	{
	case RS_PKT_SUBTYPE_MOBILE_LINK_HELLO: return new RsMobileLinkHelloItem();
	case RS_PKT_SUBTYPE_MOBILE_LINK_HOME:  return new RsMobileLinkHomeItem();
	case RS_PKT_SUBTYPE_MOBILE_LINK_STATE: return new RsMobileLinkStateItem();
	case RS_PKT_SUBTYPE_MOBILE_LINK_PING:  return new RsMobileLinkPingItem();
	case RS_PKT_SUBTYPE_MOBILE_LINK_PONG:  return new RsMobileLinkPongItem();
	case RS_PKT_SUBTYPE_MOBILE_LINK_KEEP_ALIVE_STOCK:
		return new RsMobileLinkKeepAliveStockItem();
	default: return nullptr;
	}
}
