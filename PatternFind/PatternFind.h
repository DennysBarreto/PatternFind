#pragma once

#include <vector>
#include <cstdint>

_Success_(return != nullptr)
std::pair<std::vector<int32_t>, size_t> QueryPatternData(
    _In_ const char* Pattern
);

_Success_(return != 0)
DWORD64 FindPatternModuleExternal(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR ModuleBase,
    _In_ LPCSTR sSignature,
    _In_ ULONG nSelectResultIndex
);

_Success_(return != 0)
DWORD64 FindPatternRegionExternalEx(
    _In_ HANDLE hProcess,
    _In_ DWORD64 ScanBase,
    _In_ ULONG ScanSize,
    _In_ LPCSTR sSignature,
    _In_ ULONG nSelectResultIndex,
    _Out_opt_ PULONG nPatternSize
);

_Success_(return != 0)
DWORD64 FindPatternRegionExternal(
    _In_ HANDLE hProcess,
    _In_ DWORD64 ScanBase,
    _In_ ULONG ScanSize,
    _In_ LPCSTR sSignature,
    _In_ ULONG nSelectResultIndex
);

_Success_(return != 0)
ULONG_PTR FindPatternRegionLocalEx(
    _In_ ULONG_PTR ScanBase,
    _In_ ULONG ScanSize,
    _In_ LPCSTR sSignature,
    _In_ ULONG nSelectResultIndex,
    _Out_opt_ PULONG nPatternSize
);

_Success_(return != 0)
ULONG_PTR FindPatternRegionLocal(
    _In_ ULONG_PTR ScanBase,
    _In_ ULONG ScanSize,
    _In_ LPCSTR sSignature,
    _In_ ULONG nSelectResultIndex
);

_Success_(return != 0)
ULONG_PTR FindPatternModuleLocal(
    _In_ ULONG_PTR ModuleBase,
    _In_ LPCSTR sSignature,
    _In_ ULONG nSelectResultIndex
);