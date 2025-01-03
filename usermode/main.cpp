#include <Windows.h>
#include <iostream>
#include "driver.h"
#include "thread"
namespace offsets
{
	WORD uworld = 0x60;
}
auto cachethread() -> void
{
	auto pml4base = driver::get_guarded();
	printf("pml4base: 0x%p\n", pml4base);

	while (true)
	{
		auto uworld = read<uintptr_t>(pml4base + 0x60);
		printf("uworld: 0x%p\n", uworld);

		Sleep(2000);
	}
}

auto main() -> const NTSTATUS
{
	auto process = driver::FindProcessID(L"VALORANT-Win64-Shipping.exe");

	printf("processid: %i\n", process);

	if (process != 0)
	{
		driver::Init();

		std::thread(cachethread).detach();
	}

	getchar();
	return 0;
}