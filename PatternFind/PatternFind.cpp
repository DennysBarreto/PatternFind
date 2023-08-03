#include <windows.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <utility>

#include "ntdll.h"
#include "PatternFind.h"

#pragma warning(disable: 4244)
#pragma warning(disable: 4267)

std::pair<std::vector<int32_t>, size_t> QueryPatternData(const char* Pattern) 
{
	auto bytes = std::vector<int32_t>();
	auto start = const_cast<char*>(Pattern);
	const auto end = Pattern + strlen(Pattern);

	for (auto current = start; current < end; ++current)
	{
		if (*current == '?')
		{
			++current;

			if (*current == '?')
			{
				++current;
			}

			bytes.push_back(-1);
		}
		else
		{
			bytes.push_back(static_cast<int32_t>(strtoul(current, &current, 16)));
		}
	}

	return std::make_pair(bytes, bytes.size());
}

DWORD64 __stdcall FindPatternModuleExternal(
	_In_ HANDLE hProcess,
	_In_ ULONG_PTR ModuleBase,
	_In_ LPCSTR sSignature,
	_In_ ULONG nSelectResultIndex
)
{
	NTSTATUS Status = 0;
	MEMORY_BASIC_INFORMATION mMemInfo = { 0 };
	SIZE_T nReadBytes = 0;
	PVOID pAllocateBase = 0;
	DWORD64 Result = 0;

	ULONG nResultPos = 0;
	ULONG nPatternSize = 0;
	DWORD64 TempResult = 0;

	Status = NtQueryVirtualMemory(hProcess, (PVOID)ModuleBase,
		MemoryBasicInformation, &mMemInfo, sizeof(mMemInfo), &nReadBytes);

	if (Status == STATUS_SUCCESS)
	{
		pAllocateBase = mMemInfo.AllocationBase;

		do {

			if (!(FlagOn(mMemInfo.RegionSize, PAGE_NOACCESS | PAGE_GUARD)))
			{
				ULONG_PTR pNextRegionSearch = (ULONG_PTR)mMemInfo.BaseAddress;
				ULONG uNextRegionSearchSize = mMemInfo.RegionSize;
				const ULONG pSearchLimit = pNextRegionSearch + uNextRegionSearchSize;

				do {
					TempResult = ::FindPatternRegionExternalEx(
						hProcess,
						pNextRegionSearch,
						uNextRegionSearchSize,
						sSignature,
						0,
						&nPatternSize);

					if (TempResult)
					{
						if (nResultPos == nSelectResultIndex)
						{
							Result = TempResult;
							break;
						}

						// Increase result index
						nResultPos++;

						// Update next check
						uNextRegionSearchSize = mMemInfo.RegionSize - (TempResult - (ULONG_PTR)mMemInfo.BaseAddress + nPatternSize);
						pNextRegionSearch = TempResult + nPatternSize;

						// Limit exceeded check
						if ((pNextRegionSearch + uNextRegionSearchSize) > pSearchLimit)
						{
							break;
						}
					}

				} while (TempResult);
			}

			Status = NtQueryVirtualMemory(hProcess,
				PTR_ADD_OFFSET(mMemInfo.BaseAddress, mMemInfo.RegionSize),
				MemoryBasicInformation,
				&mMemInfo,
				sizeof(mMemInfo),
				&nReadBytes);

		} while (Status == STATUS_SUCCESS &&
			mMemInfo.AllocationBase == pAllocateBase &&
			Result == 0);
	}

	return Result;
}

DWORD64 __stdcall FindPatternRegionExternalEx(
	_In_ HANDLE hProcess,
	_In_ DWORD64 ScanBase,
	_In_ ULONG ScanSize,
	_In_ LPCSTR sSignature,
	_In_ ULONG nSelectResultIndex,
	_Out_opt_ PULONG nPatternSize)
{
	static CONST ULONG LOCAL_BUFFER_SIZE = 1024 * 512; // 512KB

	ULONG nRemainingSize = ScanSize;
	PVOID lpLocalBuffer = NULL;
	DWORD64 lpResult = NULL;
	ULONG nCursorOffset = NULL;
	ULONG nResultPos = 0;

	if ((ULONG_PTR)hProcess == (ULONG_PTR)NtCurrentProcess())
	{
		return (DWORD64)::FindPatternRegionLocal(ScanBase, ScanSize, sSignature, nSelectResultIndex);
	}

	lpLocalBuffer = VirtualAlloc(NULL, LOCAL_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!lpLocalBuffer)
	{
		return NULL;
	}

	do {
		SIZE_T nReadBytes = 0;
		ULONG_PTR nLocalVaResult = 0;
		ULONG_PTR nLocalRvaResult = 0;
		PVOID64 pTargetAddress = PTR64_ADD_OFFSET(ScanBase, nCursorOffset);

		if (!ReadProcessMemory(hProcess,
			pTargetAddress, lpLocalBuffer,
			min(LOCAL_BUFFER_SIZE, nRemainingSize),
			&nReadBytes))
		{
			break;
		}

		// Setup remain offset cursor
		nRemainingSize -= nReadBytes;

		ULONG_PTR pNextRegionSearch = (ULONG_PTR)lpLocalBuffer;
		ULONG uNextRegionSearchSize = nReadBytes;
		ULONG uPatternSize = 0;
		ULONG pSearchLimit = (ULONG_PTR)lpLocalBuffer + nReadBytes;

		do {

			nLocalVaResult = ::FindPatternRegionLocalEx(
				pNextRegionSearch,
				uNextRegionSearchSize, sSignature,
				0,
				&uPatternSize);

			if (nPatternSize)
			{
				*nPatternSize = uPatternSize;
			}

			if (nLocalVaResult)
			{
				// Get RVA calculating local VA result from buffer
				nLocalRvaResult = nLocalVaResult - (ULONG_PTR)lpLocalBuffer;

				if (nResultPos == nSelectResultIndex)
				{
					// Real external pointer
					lpResult = (DWORD64)PTR64_ADD_OFFSET(pTargetAddress, nLocalRvaResult);

					break;
				}

				// Increase result index
				nResultPos++;

				// Update next scan
				uNextRegionSearchSize = pSearchLimit - (nLocalVaResult + uPatternSize);
				pNextRegionSearch = nLocalVaResult + uPatternSize;

				// Limit exceeded
				if ((pNextRegionSearch + uNextRegionSearchSize) > pSearchLimit)
				{
					break;
				}
			}

		} while (nLocalVaResult);

		// Setup current cursor offset
		nCursorOffset += nReadBytes;

	} while (nRemainingSize > 0 && lpResult == 0);

	VirtualFree(lpLocalBuffer, NULL, MEM_RELEASE);

	return lpResult;
}

DWORD64 __stdcall FindPatternRegionExternal(
	_In_ HANDLE hProcess,
	_In_ DWORD64 ScanBase,
	_In_ ULONG ScanSize,
	_In_ LPCSTR sSignature,
	_In_ ULONG nSelectResultIndex)
{
	return FindPatternRegionExternalEx(hProcess, ScanBase, ScanSize, sSignature, nSelectResultIndex, 0);
}

ULONG_PTR __stdcall FindPatternRegionLocalEx(
	_In_ ULONG_PTR ScanBase,
	_In_ ULONG ScanSize,
	_In_ LPCSTR sSignature,
	_In_ ULONG nSelectResultIndex,
	_Out_opt_ PULONG nPatternSize
)
{
	auto PatternInfo = QueryPatternData(sSignature);

	const auto s = PatternInfo.second;
	const auto d = PatternInfo.first.data();
	const auto scanBytes = reinterpret_cast<std::uint8_t*>(ScanBase);

	size_t nFoundResults = 0;

	if (nPatternSize)
	{
		*nPatternSize = s;
	}

	for (auto i = 0ul; i < ScanSize - s; ++i)
	{
		bool found = true;

		for (auto j = 0ul; j < s; ++j)
		{
			if (scanBytes[i + j] != d[j] && d[j] != -1)
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			if (nSelectResultIndex != 0)
			{
				if (nFoundResults < nSelectResultIndex)
				{
					nFoundResults++;
					found = false;
				}
				else
				{
					return (ULONG_PTR)(&scanBytes[i]);
				}
			}
			else
			{
				return (ULONG_PTR)(&scanBytes[i]);
			}
		}
	}

	return NULL;
}

ULONG_PTR __stdcall FindPatternRegionLocal(
	_In_ ULONG_PTR ScanBase,
	_In_ ULONG ScanSize,
	_In_ LPCSTR sSignature,
	_In_ ULONG nSelectResultIndex
)
{
	return FindPatternRegionLocalEx(ScanBase, ScanSize, sSignature, nSelectResultIndex, 0);
}

ULONG_PTR __stdcall FindPatternModuleLocal(
	_In_ ULONG_PTR ModuleBase,
	_In_ LPCSTR sSignature,
	_In_ ULONG nSelectResultIndex
)
{
	PLDR_DATA_TABLE_ENTRY Entry = NULL;

	LdrFindEntryForAddress((LPVOID)ModuleBase, &Entry);

	if (!Entry)
	{
		return NULL;
	}

	return FindPatternRegionLocal((ULONG_PTR)Entry->DllBase, Entry->SizeOfImage, sSignature, nSelectResultIndex);
}