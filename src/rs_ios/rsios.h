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

/* C interface the iOS application (Swift) uses to run the RetroShare core in
 * its own process: the iOS counterpart of rs_android/. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialise the core and start the JSON API.
 * @param baseDir directory holding the profiles, inside the application
 *	sandbox (the default $HOME/.retroshare is not writable on iOS)
 * @return 0 on success, the RsInit::InitRetroShare error code otherwise,
 *	-1 on invalid arguments
 */
int rs_ios_start(const char* baseDir, int jsonApiPort, const char* jsonApiBindAddress);

/** Shut the core down. Returns once it has stopped. */
void rs_ios_stop(void);

/** @return 1 between a successful rs_ios_start() and rs_ios_stop(), else 0 */
int rs_ios_is_running(void);

#ifdef __cplusplus
}
#endif
