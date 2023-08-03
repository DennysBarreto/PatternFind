#include <windows.h>
#include <iostream>
#include <array>

#include "PatternFind.h"

constexpr std::array<unsigned char, 6> byteArray1 = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC };
constexpr std::array<unsigned char, 7> byteArray2 = { 0xFF, 0x00, 0x55, 0xAA, 0x77, 0x33, 0x88 };
constexpr std::array<unsigned char, 8> byteArray3 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
constexpr std::array<unsigned char, 9> byteArray4 = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE, 0xFA };
constexpr std::array<unsigned char, 10> byteArray5 = { 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };

void RunStaticTests()
{
	struct tests_ctx{
		const char* szSignature;
		const unsigned char* pScanData;
	}tests[] =
	{
		{ "12 ?? 56 78 ?? BC", byteArray1.data() },
		{ "FF ?? 55 AA 77 ?? 88", byteArray2.data() },
		{ "01 23 ?? 67 ?? AB CD EF", byteArray3.data() },
		{ "DE AD BE ?? ?? ?? FA CE FA", byteArray4.data() },
		{ "55 66 77 88 ?? AA BB ?? DD EE", byteArray5.data() }
	};

	const PVOID hModule = GetModuleHandleW(0);

	for (const auto& test : tests)
	{
		const auto result = (void*)FindPatternModuleLocal((ULONG_PTR)hModule, test.szSignature, 0);

		std::cout << "FindResult: " << result << " - Original: " << (void*)test.pScanData << std::endl;
	}
}

int main()
{
	RunStaticTests();

	return 0;
}