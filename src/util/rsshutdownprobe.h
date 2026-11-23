/*******************************************************************************
 * libretroshare/src/util: rsshutdownprobe.h                                   *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
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

/* Shutdown diagnostics (debug/shutdown-step-timings, not for upstream): the
 * memory figures of the process, to put on each timed shutdown line.
 *
 * On a node that ran for a day the shutdown steps that walk memory untouched
 * for hours (destroying the main window, freeing the caches of the databases)
 * take several times longer than after a short run. If Windows moved that
 * memory to the page file, it reads it back page by page during the shutdown:
 * the page fault count of a step and the working set before and after it tell.
 *
 * Windows only (GetProcessMemoryInfo). Its page fault count includes the soft
 * faults; a page read back from the page file is one of them. Elsewhere the
 * figures are not measured and nothing is added to the lines. Header-only, so
 * that the library and the GUI share it without an exported symbol. */

#include <chrono>
#include <cstdint>
#include <string>

#ifdef _WIN32
#	ifndef NOMINMAX
#		define NOMINMAX
#	endif
/* Included in the middle of files, after their own headers: lean, so that it
 * brings no COM macros ("interface") into the code that follows. */
#	ifndef WIN32_LEAN_AND_MEAN
#		define WIN32_LEAN_AND_MEAN
#		define RS_SHUTDOWNPROBE_LEAN
#	endif
#	include <windows.h>
#	include <psapi.h>     // PROCESS_MEMORY_COUNTERS only: the call is looked up
#	ifdef RS_SHUTDOWNPROBE_LEAN
#		undef WIN32_LEAN_AND_MEAN
#		undef RS_SHUTDOWNPROBE_LEAN
#	endif
#endif

struct RsShutdownMem
{
	bool ok = false;
	uint64_t pageFaults = 0;
	uint64_t workingSet = 0; ///< bytes of the process in RAM
	uint64_t pagefile = 0;   ///< private bytes committed (backed by the page file)

	static RsShutdownMem now()
	{
		RsShutdownMem m;
#ifdef _WIN32
		using GetMemoryInfoFn = BOOL (WINAPI*)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
		// kernel32 export since Windows 7: no psapi.dll to link
		static const GetMemoryInfoFn getMemoryInfo = reinterpret_cast<GetMemoryInfoFn>(
		        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
		                                               "K32GetProcessMemoryInfo")));
		PROCESS_MEMORY_COUNTERS pmc;
		ZeroMemory(&pmc, sizeof(pmc));
		pmc.cb = sizeof(pmc);
		if(getMemoryInfo && getMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
		{
			m.ok = true;
			m.pageFaults = pmc.PageFaultCount;
			m.workingSet = pmc.WorkingSetSize;
			m.pagefile = pmc.PagefileUsage;
		}
#endif
		return m;
	}

	/** ", page faults +N, working set A -> B MB, page file C -> D MB" from
	 * @p before to this one, or an empty string where it is not measured. */
	std::string since(const RsShutdownMem& before) const
	{
		if(!ok || !before.ok) return std::string();
		return ", page faults +" + std::to_string(pageFaults - before.pageFaults)
		     + ", working set " + std::to_string(before.workingSet >> 20) + " -> "
		     + std::to_string(workingSet >> 20) + " MB, page file "
		     + std::to_string(before.pagefile >> 20) + " -> " + std::to_string(pagefile >> 20) + " MB";
	}
};

/** Start of the shutdown step in progress (set by the library's ShutdownStep),
 * for a line written from inside the step to split it in two. */
struct RsShutdownStepStart
{
	std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
	RsShutdownMem mem;

	static RsShutdownStepStart& current() { static RsShutdownStepStart s; return s; }

	/// "N ms" since the start of the step, then its memory figures
	std::string elapsed() const
	{
		return std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
		                          std::chrono::steady_clock::now() - t0).count())
		     + " ms" + RsShutdownMem::now().since(mem);
	}
};
