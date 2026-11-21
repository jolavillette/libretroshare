/*******************************************************************************
 * libretroshare/src/pqi: pqithreadstreamer.cc                                 *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright 2004-2013 by Robert Fernie <retroshare@lunamutt.com>              *
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
#include "util/rstime.h"
#include "pqi/pqithreadstreamer.h"
#include <algorithm>
#include <chrono>
#include <unistd.h>

// for timeBeginPeriod
#ifdef WINDOWS_SYS
#include <windows.h>
#include <mmsystem.h>
#endif

#define STREAMER_TIMEOUT_MIN                  0 //  non blocking
#define STREAMER_TIMEOUT_DELTA		   1000 //  1 ms
#define STREAMER_TIMEOUT_MAX              10000 // 10 ms

#define STREAMER_SLEEP_MIN		   1000 //  1 ms
#define STREAMER_SLEEP_DELTA               1000 //  1 ms
#define STREAMER_SLEEP_MAX                30000 // 30 ms

#define DEFAULT_STREAMER_IDLE_SLEEP	1000000 //  1 sec

// #define PQISTREAMER_DEBUG

pqithreadstreamer::pqithreadstreamer(PQInterface *parent, RsSerialiser *rss, const RsPeerId& id, BinInterface *bio_in, int bio_flags_in)
:pqistreamer(rss, id, bio_in, bio_flags_in), mParent(parent), mTimeout(0), mThreadMutex("pqithreadstreamer")
{
#ifdef WINDOWS_SYS
        // On Windows, the default system timer resolution is around 15 ms.
        // This call allows for sleep durations of less than 15 ms, which is
        // necessary for frequent polling and high-speed data transfer.
        timeBeginPeriod(1);
#endif
	mTimeout = STREAMER_TIMEOUT_MAX;
	mSleepPeriod = STREAMER_SLEEP_MAX;
}

bool pqithreadstreamer::RecvItem(RsItem *item)
{
	return mParent->RecvItem(item);
}

int	pqithreadstreamer::SendItem(RsItem *item, uint32_t& serialized_size)
{
	int ret = pqistreamer::SendItem(item, serialized_size);	// item may be deleted by now

	// An idle streamer sleeps up to STREAMER_SLEEP_MAX: without this, the item would wait
	// for the end of that sleep. Notifying costs next to nothing when the thread is not waiting.
	{
		std::lock_guard<std::mutex> lock(mWakeMtx);
		mItemQueued = true;
	}
	mWakeCv.notify_one();

	return ret;
}

int	pqithreadstreamer::tick()
{
	// pqithreadstreamer mutex lock is not needed here
	// we only check if the connection is active, and if not we will try to establish it
	tick_bio();

	return 0;
}

int	pqithreadstreamer::reset()
{
	// handleincoming() fills the read buffers without holding mStreamerMtx, under
	// mThreadMutex only: wait for a running tick_recv()/tick_send() to finish
	// before pqistreamer::reset() frees them.
	RsStackMutex stack(mThreadMutex);
	return pqistreamer::reset();
}

void pqithreadstreamer::threadTick()
{
        uint32_t readbytes = 0;
        uint32_t sentbytes = 0;
	bool isactive = false;

	// Locked section to safely read shared variables
	{
		RsStackMutex stack(mStreamerMtx);
		isactive = mBio->isactive();
	}
    
	// Long sleep if connection is not active
	if (!isactive)
	{
//		RsDbg() << "PQISTREAMER pqithreadstreamer::threadTick() mBio->isactive() false long sleep";
		rstime::rs_usleep(DEFAULT_STREAMER_IDLE_SLEEP);
		return ;
	}

	updateRates();

	// An item queued since the last send (it may be what woke us up) goes out first: do not let
	// the poll for incoming data hold it back for up to mTimeout.
	bool itemQueued;
	{
		std::lock_guard<std::mutex> lock(mWakeMtx);
		itemQueued = mItemQueued;
	}

	// Fill incoming queue
	{
		RsStackMutex stack(mThreadMutex);
		readbytes = tick_recv(itemQueued ? STREAMER_TIMEOUT_MIN : mTimeout);
	}

	// Process incoming items, move them to relevant service queue or shortcut to fast service
	RsItem *incoming = NULL;
	while((incoming = GetItem()))
	{
		RecvItem(incoming);
	}

	// Everything queued until now is handled by the send below. An item queued from here on sets
	// the flag again, and the wait at the end of this pass returns at once.
	{
		std::lock_guard<std::mutex> lock(mWakeMtx);
		mItemQueued = false;
	}

	// Parse outgoing queue and send items
	{
		RsStackMutex stack(mThreadMutex);
		sentbytes = tick_send(0);
	}

	const bool queueEmpty = (getQueueSize(false) == 0);

        // Adaptive timeout and sleep. Reading, or a send that left items queued, means a transfer:
        // go reactive. A send that emptied the queue is a lone item (on a node with many friends,
        // mostly forwarded turtle tunnel requests, several per second on every link): treating it as
        // activity kept every idle link at a 1 ms cadence. The next lone item does not wait for the
        // end of the sleep: SendItem() wakes the thread (see below).
        if (readbytes > 0 || (sentbytes > 0 && !queueEmpty))
        {
                // Activity detected: switch to maximum reactivity immediately
                // This ensure fast throughput for data bursts
                mTimeout = STREAMER_TIMEOUT_MIN;
                mSleepPeriod = STREAMER_SLEEP_MIN;
        }
        else
        {
                // No activity: back off geometrically. Any byte resets both to their minimum, and on a
                // node with many friends turtle traffic touches every link every few tens of ms: with
                // a +1 ms ramp a link never got past a few ms of sleep (measured ~150 wakeups/s per
                // peer thread). Doubling reaches the maximum in a handful of idle passes.
                mTimeout = std::min<uint32_t>(STREAMER_TIMEOUT_MAX, std::max<uint32_t>(STREAMER_TIMEOUT_DELTA, 2*mTimeout));
                mSleepPeriod = std::min<uint32_t>(STREAMER_SLEEP_MAX, std::max<uint32_t>(STREAMER_SLEEP_DELTA, 2*mSleepPeriod));
        }

	// RsDbg() << "PQISTREAMER " << threadName() << " pqithreadstreamer::threadTick() mTimeout " << std::dec << mTimeout / 1000 << " mSleepPeriod " <<  mSleepPeriod / 1000 << " readbytes " << readbytes << "  sentbytes " << sentbytes;

	if (mSleepPeriod > 0)
	{
		// Queue empty: sleep until the period ends or SendItem() queues an item. Lone items are
		// mostly turtle tunnel requests and results, whose arrival order decides which route a
		// tunnel takes; holding them up to a full idle cycle on every hop favoured the routes
		// made of busy links. Items left in the queue (bandwidth limit, socket full): plain
		// sleep, or every item queued behind them would cost a pass that cannot send it.
		if (queueEmpty)
			waitForItemOrTimeout(mSleepPeriod);
		else
			rstime::rs_usleep(mSleepPeriod);
	}
}

void pqithreadstreamer::waitForItemOrTimeout(uint32_t usec)
{
	std::unique_lock<std::mutex> lock(mWakeMtx);
	mWakeCv.wait_for(lock, std::chrono::microseconds(usec), [this] { return mItemQueued; });
}
