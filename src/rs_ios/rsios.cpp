/*
 * RetroShare iOS entry points
 * Copyright (C) 2026  Retroshare Team <contact@retroshare.cc>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-FileCopyrightText: Retroshare Team <contact@retroshare.cc>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cstdint>
#include <limits>
#include <mutex>
#include <string>

#include "retroshare/rsinit.h"
#include "retroshare/rsiface.h"
#include "util/rsdebug.h"

#include "rs_ios/rsios.h"

namespace
{
std::mutex sMutex;
bool sRunning = false;
}

int rs_ios_start(const char* baseDir, int jsonApiPort, const char* jsonApiBindAddress)
{
	std::lock_guard<std::mutex> lock(sMutex);
	if(sRunning) return 0;

	if( !baseDir || !jsonApiBindAddress || jsonApiPort < 0 ||
	        jsonApiPort > std::numeric_limits<uint16_t>::max() )
	{
		RS_ERR("Invalid arguments");
		return -1;
	}

	RsInit::InitRsConfig();
	RsControl::earlyInitNotificationSystem();

	RsConfigOptions conf;
	conf.optBaseDir = baseDir;
	conf.jsonApiPort = static_cast<uint16_t>(jsonApiPort);
	conf.jsonApiBindAddress = jsonApiBindAddress;

	// Plugins are not supported on iOS
	conf.main_executable_path = " ";

	const int initResult = RsInit::InitRetroShare(conf);
	if(initResult != RS_INIT_OK)
	{
		RS_ERR("Retroshare core initalization failed with: ", initResult);
		return initResult;
	}

#ifdef RS_JSONAPI
	RsInit::startupWebServices(conf, true);
#endif

	sRunning = true;
	return 0;
}

void rs_ios_stop(void)
{
	std::lock_guard<std::mutex> lock(sMutex);
	if(!sRunning) return;
	RsControl::instance()->rsGlobalShutDown();
	sRunning = false;
}

int rs_ios_is_running(void)
{
	std::lock_guard<std::mutex> lock(sMutex);
	return sRunning ? 1 : 0;
}
