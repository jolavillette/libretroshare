/*******************************************************************************
 * libretroshare/src/rsitems: rsmobilepushitems.cc                             *
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
#include "rsitems/rsmobilepushitems.h"

RsItem* RsMobilePushSerialiser::create_item(uint16_t service, uint8_t subtype) const
{
	if(service != static_cast<uint16_t>(RsServiceType::MOBILE_PUSH))
		return nullptr;

	switch(subtype)
	{
	case RS_PKT_SUBTYPE_MOBILE_PUSH_REGISTRATION:
		return new RsMobilePushRegistrationItem();
	case RS_PKT_SUBTYPE_MOBILE_PUSH_PREFERENCES:
		return new RsMobilePushPreferencesItem();
	default: return nullptr;
	}
}
