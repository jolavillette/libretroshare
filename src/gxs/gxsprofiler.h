/*******************************************************************************
 * libretroshare/src/gxs: gxsprofiler.h                                        *
 *                                                                             *
 * Diagnostic probe for GXS service-thread latency.                            *
 *                                                                             *
 * Silent in normal operation: a probed section is only reported when it       *
 * exceeds the slow threshold (RS_GXS_PROF_MS environment variable,            *
 * default 1000 ms). Output tag: GXS-PROF.                                     *
 ******************************************************************************/
#pragma once

#include <chrono>
#include <cstdlib>

#include "util/rsdebug.h"

/**
 * Scoped step timer for a GXS service loop.
 *
 * Usage:
 *   GxsTickProfiler prof(mServType, "RsGenExchange::tick()");
 *   prof.step("stepA"); stepA();
 *   prof.step("stepB"); stepB();
 *   // destructor closes the last step and reports the total if slow
 */
class GxsTickProfiler
{
public:
	GxsTickProfiler(uint16_t serviceType, const char* context)
	    : mServiceType(serviceType), mContext(context), mStepName(nullptr)
	{
		mStart = mStepStart = std::chrono::steady_clock::now();
	}

	~GxsTickProfiler()
	{
		closeStep();

		int64_t total = msSince(mStart);
		if(total >= slowThresholdMs())
			RsWarn() << "GXS-PROF service 0x" << std::hex << mServiceType
			         << std::dec << " " << mContext << " full pass took "
			         << total << " ms" << std::endl;
	}

	/// Close the previous step (if any) and start a new one.
	void step(const char* name)
	{
		closeStep();
		mStepName = name;
		mStepStart = std::chrono::steady_clock::now();
	}

	/// Threshold above which a section is reported, in milliseconds.
	static int64_t slowThresholdMs()
	{
		static int64_t t = [] {
			const char* s = std::getenv("RS_GXS_PROF_MS");
			int64_t v = s ? std::atoll(s) : 0;
			return v > 0 ? v : 1000;
		}();
		return t;
	}

	GxsTickProfiler(const GxsTickProfiler&) = delete;
	GxsTickProfiler& operator=(const GxsTickProfiler&) = delete;

private:
	static int64_t msSince(const std::chrono::steady_clock::time_point& t0)
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(
		            std::chrono::steady_clock::now() - t0).count();
	}

	void closeStep()
	{
		if(!mStepName) return;

		int64_t ms = msSince(mStepStart);
		if(ms >= slowThresholdMs())
			RsWarn() << "GXS-PROF service 0x" << std::hex << mServiceType
			         << std::dec << " " << mContext << " step " << mStepName
			         << " took " << ms << " ms" << std::endl;
		mStepName = nullptr;
	}

	uint16_t mServiceType;
	const char* mContext;
	const char* mStepName;
	std::chrono::steady_clock::time_point mStart;
	std::chrono::steady_clock::time_point mStepStart;
};
