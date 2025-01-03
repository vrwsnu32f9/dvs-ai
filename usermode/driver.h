#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>

uintptr_t guarded_region;

#define read_ctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x13f0, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define base_addy_ctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x13f1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define cr3_van_ctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x13f2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _r {
	INT32 Security;
	INT32 ProcessId;
	ULONGLONG Address;
	ULONGLONG Buffer;
	ULONGLONG Size;
	BOOLEAN Write;
} r, * pr;

typedef struct _b {
	INT32 Security;
	INT32 ProcessId;
	ULONGLONG* Address;
} b, * pb;

//guarded region struct
typedef struct _gr {
	ULONGLONG* guarded;
} gr, * pgr;


namespace driver {
	HANDLE DriverHandle;
	INT32 ProcessIdentifier;

	bool Init() {
		DriverHandle = CreateFileW((L"\\\\.\\\BrazilOnTopVGH"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (!DriverHandle || (DriverHandle == INVALID_HANDLE_VALUE))
			return false;

		return true;
	}

	void ReadPhysical(PVOID address, PVOID buffer, DWORD size) {
		_r arguments = { 0 };

		arguments.Address = (ULONGLONG)address;
		arguments.Buffer = (ULONGLONG)buffer;
		arguments.Size = size;
		arguments.ProcessId = ProcessIdentifier;
		arguments.Write = FALSE;

		DeviceIoControl(DriverHandle, read_ctl, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	uintptr_t GetBaseAddress() {
		uintptr_t image_address = { NULL };
		_b arguments = { NULL };

		arguments.ProcessId = ProcessIdentifier;
		arguments.Address = (ULONGLONG*)&image_address;

		DeviceIoControl(DriverHandle, base_addy_ctl, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

		return image_address;
	}

	auto get_guarded() -> uintptr_t
	{
		uintptr_t shadow_g = { NULL };
		_gr input = { 0 };

		input.guarded = (ULONGLONG*)&shadow_g;

		DeviceIoControl(DriverHandle, cr3_van_ctl, &input, sizeof(input), nullptr, NULL, NULL, NULL);

		return shadow_g;
	}
	INT32 FindProcessID(LPCTSTR process_name) {
		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, process_name)) {
					CloseHandle(hsnap);
					ProcessIdentifier = pt.th32ProcessID;
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);

		return { NULL };
	}
}

template <typename T>
T read(uint64_t address) {
	T buffer{ };
	driver::ReadPhysical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}

bool IsValid(const uint64_t adress)
{
	if (adress <= 0x400000 || adress == 0xCCCCCCCCCCCCCCCC || reinterpret_cast<void*>(adress) == nullptr || adress >
		0x7FFFFFFFFFFFFFFF) {
		return false;
	}
	return true;
}
template<typename T>
bool ReadArray(uintptr_t address, T out[], size_t len)
{
	for (size_t i = 0; i < len; ++i)
	{
		out[i] = read<T>(address + i * sizeof(T));
	}
	return true; // you can add additional checks to verify successful reads
}

template<typename T>
bool ReadArray2(uint64_t address, T* out, size_t len)
{
	if (!driver::DriverHandle || driver::DriverHandle == INVALID_HANDLE_VALUE)
	{
		if (!driver::Init())
		{
			return false;
		}
	}

	if (!out || len == 0)
	{
		return false;
	}

	for (size_t i = 0; i < len; ++i)
	{
		if (!IsValid(address + i * sizeof(T)))
		{
			return false;
		}

		out[i] = read<T>(address + i * sizeof(T));
	}
	return true;
}