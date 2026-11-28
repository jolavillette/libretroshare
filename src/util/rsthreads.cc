/*******************************************************************************
 * libretroshare/src/util: rsthreads.cc                                        *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright (C) 2004-2007  Robert Fernie <retroshare@lunamutt.com>            *
 * Copyright (C) 2016-2021  Gioacchino Mazzurco <gio@retroshare.cc>             *
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

#include "rsthreads.h"

#include "util/rsdebug.h"

#include <chrono>
#include <ctime>
#include <iostream>
#include <thread>

#ifdef RS_MUTEX_DEBUG
#include <cstdio>
#include <sys/time.h>
#endif

#ifdef __APPLE__
int __attribute__((weak)) pthread_setname_np(const char *__buf) ;
int RS_pthread_setname_np(pthread_t /*__target_thread*/, const char *__buf) {
	return pthread_setname_np(__buf);
}
#else
#ifndef __WIN64__
int __attribute__((weak)) pthread_setname_np(pthread_t __target_thread, const char *__buf) ;
#endif //__WIN64__
int RS_pthread_setname_np(pthread_t __target_thread, const char *__buf) {
	return pthread_setname_np(__target_thread, __buf);
}
#endif //__APPLE__


/*******
 * #define DEBUG_THREADS 1
 * #define RSMUTEX_ABORT 1  // Catch wrong pthreads mode.
 *******/
#define THREAD_DEBUG RsDbg() << "[this=" << static_cast<void*>(this) \
	<< ", caller thread ID: " << std::hex << pthread_self() << ", thread ID: " \
	<< mTid << std::dec << "] "

#ifdef RSMUTEX_ABORT
	#include <stdlib.h>
#endif

#ifdef DEBUG_THREADS
	#include <iostream>
#endif

#include <sys/time.h>
static double getCurrentTS()
{
#ifndef WINDOWS_SYS
        struct timeval cts_tmp;
        gettimeofday(&cts_tmp, NULL);
        double cts =  (cts_tmp.tv_sec) + ((double) cts_tmp.tv_usec) / 1000000.0;
#else
        struct _timeb timebuf;
        _ftime( &timebuf);
        double cts =  (timebuf.time) + ((double) timebuf.millitm) / 1000.0;
#endif
        return cts;
}

/* On Windows, with the winpthreads of MSYS2, every detached thread leaves one
 * handle open for the rest of the process, whichever side detaches it
 * (measured: 500 detached threads, 500 handles more; 500 joined threads, none).
 * A node starts hundreds of short-lived threads an hour, and reached 180 000
 * handles after a few days. So on Windows the threads are not detached: a
 * thread that ends puts itself in a list, and the next call that creates a
 * thread joins the threads of that list first. Joining a thread that is
 * returning takes no time, and the list never holds more than the threads that
 * ended since the last creation.
 *
 * WORKAROUND, TO BE REMOVED: this is a defect of winpthreads, not of our code:
 * one Event handle (the spin_keys of the thread) is lost for every detached
 * thread that exits. Reported as mingw-w64 issue 190,
 * https://github.com/mingw-w64/mingw-w64/issues/190, seen with winpthreads
 * 14.0.0.r598.ge3d18511f. Once the MSYS2 package used for the builds carries
 * the fix, remove RS_THREAD_JOIN_FINISHED and everything under it: the threads
 * are detached again as on the other platforms.
 * How to check after an MSYS2 update: a program that starts 500 threads which
 * call pthread_detach(pthread_self()) and return, with GetProcessHandleCount()
 * before and two seconds after: +500 handles = still needed, about +0 = this
 * can go. The same leak, one handle per thread, remains in the few places that
 * still detach on Windows: util/dnsresolver.cc and the two rs_upnp handlers. */
#ifdef WINDOWS_SYS
#	define RS_THREAD_JOIN_FINISHED 1
#endif

#ifdef RS_THREAD_JOIN_FINISHED
#include <mutex>
#include <vector>

namespace
{
	std::mutex& finishedThreadsMutex()
	{
		static std::mutex m;
		return m;
	}
	std::vector<pthread_t>& finishedThreads()
	{
		static std::vector<pthread_t> v;
		return v;
	}

	/* Last thing a thread does. Nothing that may be deleted by someone else
	 * can be touched after this call. */
	void registerFinishedThread()
	{
		std::lock_guard<std::mutex> lock(finishedThreadsMutex());
		finishedThreads().push_back(pthread_self());
	}

	void joinFinishedThreads()
	{
		std::vector<pthread_t> to_join;
		{
			std::lock_guard<std::mutex> lock(finishedThreadsMutex());
			to_join.swap(finishedThreads());
		}

		for(const pthread_t& tid: to_join)
			pthread_join(tid, nullptr);
	}

	void* rsthread_async_init(void* p)
	{
		std::function<void()>* fn = static_cast<std::function<void()>*>(p);

		(*fn)();
		delete fn;

		registerFinishedThread();
		return nullptr;
	}
}
#endif // def RS_THREAD_JOIN_FINISHED

/*static*/ void RsThread::async(const std::function<void()>& fn)
{
#ifdef RS_THREAD_JOIN_FINISHED
	joinFinishedThreads();

	std::function<void()>* fn_copy = new std::function<void()>(fn);
	pthread_t tid;

	if(0 == pthread_create(&tid, nullptr, &rsthread_async_init, fn_copy))
		return;

	delete fn_copy;	// could not be created that way: do as before
#endif
	std::thread(fn).detach();
}

/*static*/ void* RsThread::rsthread_init(void* p)
{
	RsThread* thread = reinterpret_cast<RsThread *>(p);
	if(!thread) return nullptr;

#ifdef RS_THREAD_JOIN_FINISHED
	thread->wrapRun();

	/* The RsThread object may be deleted from now on (mHasStopped is true):
	 * do not touch it any more. */
	registerFinishedThread();
	return nullptr;
#endif

	/* Using pthread_detach(...) the thread resources will be automatically
	 * freed when this function return, so there is no need for pthread_join()
	 * later. */
	pthread_detach(pthread_self());

#ifdef DEBUG_THREADS
	std::cerr << "[Thread ID:" << std::hex << pthread_self() << std::dec
	          << "] thread is started. Calling wrapRun()..." << std::endl;
#endif

	thread->wrapRun();
	return nullptr;
}

void RsThread::resetTid()
{
#ifdef WINDOWS_SYS
	memset (&mTid, 0, sizeof(mTid));
#else
	mTid = pthread_t(); //Thread identifiers should be considered opaque and can be null.
#endif
}

RsThread::RsThread() : mInitMtx("RsThread"), mHasStopped(true),
    mShouldStop(false), mLastTid()
#ifdef RS_THREAD_FORCE_STOP
  , mStopTimeout(0)
#endif
{ resetTid(); }

bool RsThread::isRunning() { return !mHasStopped; }

bool RsThread::shouldStop() { return mShouldStop; }

void RsThread::askForStop()
{
	/* Call onStopRequested() only once even if askForStop() is called multiple
	 * times */
	if(!mShouldStop.exchange(true)) onStopRequested();
}

void RsThread::wrapRun()
{
	{RS_STACK_MUTEX(mInitMtx);} // Waiting Init done.

	/* The thread names itself: on macOS pthread_setname_np() only names the
	 * calling thread, so naming it from start() renamed the thread that
	 * started it. The name is cut to 15 characters plus the terminating null
	 * byte, the Linux limit. */
	if(pthread_setname_np && !mFullName.empty())
		RS_pthread_setname_np(pthread_self(), mFullName.substr(0, 15).c_str());

	run();
	resetTid();
	mHasStopped = true;
}

void RsThread::fullstop()
{
	askForStop();
	waitWhileStopping();
}

void RsThread::waitWhileStopping()
{
#ifdef RS_THREAD_FORCE_STOP
	const rstime_t stopRequTS = time(nullptr);
#endif

	const pthread_t callerTid = pthread_self();
	if(pthread_equal(mTid, callerTid))
	{
		RsErr() << __PRETTY_FUNCTION__ << " called by same thread. This should "
		        << "never happen! this: " << static_cast<void*>(this)
		        << std::hex << ", callerTid: " << callerTid
		        << ", mTid: " << mTid << std::dec
		        << ", mFullName: " << mFullName << std::endl;
		print_stacktrace();
		return;
	}

	// Wait for the thread being stopped
	auto i = 1;
	while(!mHasStopped)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
		++i;
		if(!(i%5))
			RsDbg() << __PRETTY_FUNCTION__ << " " << i*0.2 << " seconds passed"
			        << " waiting for thread: " << std::hex << mLastTid
			        << std::dec << " " << mFullName << " to stop" << std::endl;

#ifdef RS_THREAD_FORCE_STOP
		if(mStopTimeout && time(nullptr) > stopRequTS + mStopTimeout)
		{
			RsErr() << __PRETTY_FUNCTION__ << " thread mLastTid: " << std::hex
			         << mLastTid << " mTid: " << mTid << std::dec << " "
			         << mFullName
			         << " ignored our nice stop request for more then "
			         << mStopTimeout
			         << " seconds, will be forcefully stopped. "
			         << "Please submit a report to RetroShare developers"
			         << std::endl;

			const auto terr = pthread_cancel(mTid);
			if(terr == 0) mHasStopped = true;
			else
			{
				RsErr() << __PRETTY_FUNCTION__ << " pthread_cancel("
				        << std::hex << mTid << std::dec <<") returned "
				        << terr << " " << rs_errno_to_condition(terr)
				        << std::endl;
				print_stacktrace();
			}

			break;
		}
#endif // def RS_THREAD_FORCE_STOP
	}
}

bool RsThread::start(const std::string& threadName)
{
#ifdef RS_THREAD_JOIN_FINISHED
	joinFinishedThreads();
#endif

	// Atomically check if the thread was already started and set it as running
	if(mHasStopped.exchange(false))
	{
		RS_STACK_MUTEX(mInitMtx); // Block thread starting to run

		mShouldStop = false;
		int pError = pthread_create(
		            &mTid, nullptr, &rsthread_init, static_cast<void*>(this) );
		if(pError)
		{
			RS_ERR( "pthread_create could not create new thread: ", threadName,
			        rs_errno_to_condition(pError) );
			mHasStopped = true;
			print_stacktrace();
			return false;
		}

		/* Store an extra copy of thread id for debugging */
		mLastTid = mTid;

		/* Store thread full name as PThread is not able to keep it entirely.
		 * The new thread names itself with it in wrapRun(), once mInitMtx is
		 * released. */
		mFullName = threadName;

		return true;
	}

	RS_ERR("attempt to start already running thread: ", threadName);
	print_stacktrace();
	return false;
}

RsQueueThread::RsQueueThread(uint32_t min, uint32_t max, double relaxFactor )
    :mMinSleep(min), mMaxSleep(max), mRelaxFactor(relaxFactor)
{
    mLastSleep = (uint32_t)mMinSleep ;
    mLastWork_ms = 1000 * getCurrentTS() ;
}

void RsQueueThread::threadTick()
{
    bool doneWork = false;
    while(workQueued() && doWork())
    {
        doneWork = true;
    }
    uint64_t now_ms = 1000 * getCurrentTS();
    if (doneWork)
    {
        mLastWork_ms = now_ms;
        mLastSleep = (uint32_t) (mMinSleep + (mLastSleep - mMinSleep) / 2.0);
#ifdef DEBUG_TICKING
        THREAD_DEBUG << "RsQueueThread::data_tick() done work: sleeping for: " << mLastSleep << " ms" << std::endl;
#endif

    }
    else
    {
        uint64_t deltaT = now_ms - mLastWork_ms;
        double frac = deltaT / (1000 * mRelaxFactor);

        mLastSleep += (uint32_t)
                        ((mMaxSleep-mMinSleep) * (frac + 0.05));
        if (mLastSleep > mMaxSleep)
        {
            mLastSleep = mMaxSleep;
        }
#ifdef DEBUG_TICKING
        THREAD_DEBUG << "RsQueueThread::data_tick() no work: sleeping for: " << mLastSleep << " ms" << std::endl;
#endif
    }

	std::this_thread::sleep_for(std::chrono::milliseconds(mLastSleep));
}

void RsMutex::unlock()
{
	_thread_id = 0;
	pthread_mutex_unlock(&realMutex);
}

void RsMutex::lock()
{
	int err = pthread_mutex_lock(&realMutex);
	if( err != 0)
	{
		RsErr() << __PRETTY_FUNCTION__ << "pthread_mutex_lock returned: "
		        << rs_errno_to_condition(err)
#ifdef RS_MUTEX_DEBUG
		        << " name: " << name()
#endif
		       << std::endl;

		print_stacktrace();

#ifdef RSMUTEX_ABORT
		abort();
#endif
	}
 
	_thread_id = pthread_self();
}

#ifdef RS_MUTEX_DEBUG
double RsStackMutex::getCurrentTS()
{

#ifndef WINDOWS_SYS
        struct timeval cts_tmp;
        gettimeofday(&cts_tmp, NULL);
        double cts =  (cts_tmp.tv_sec) + ((double) cts_tmp.tv_usec) / 1000000.0;
#else
        struct _timeb timebuf;
        _ftime( &timebuf);
        double cts =  (timebuf.time) + ((double) timebuf.millitm) / 1000.0;
#endif
        return cts;
}
#endif


RsThread::~RsThread()
{
	if(!mHasStopped)
	{
		RsErr() << __PRETTY_FUNCTION__ << " deleting thread: " << mLastTid
		        << " " << mFullName << " that is still "
		        << "running! Something seems very wrong here and RetroShare is "
		        << "likely to crash because of this." << std::endl;
		print_stacktrace();

		/* Last resort attempt to stop the thread in a less pathological state.
		 * Don't call fullstop() as it rely on virtual methods that at this
		 * point are not anymore the one from inerithing classes causing
		 * compilers to output a warning */
		waitWhileStopping();
	}
}

RsQueueThread::~RsQueueThread() = default;
