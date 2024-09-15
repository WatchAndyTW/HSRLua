#pragma once
#include <Windows.h>
#include <memory>

#pragma comment(lib, "ntdll")

extern"C" int vp_syscall = 0;

extern"C" NTSTATUS virtual_protect(HANDLE ProcessHandle, PVOID BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

NTSTATUS ProtectVirtualMemory(PVOID BaseAddress, SIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
{
	return virtual_protect(GetCurrentProcess(), &BaseAddress, &NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);;
}

void hook_init()
{
	auto vp = (uint64_t)GetProcAddress(GetModuleHandle(L"ntdll"), "NtProtectVirtualMemory");
	auto prev = vp - 0x20;
	auto prev_syscall = *(uint32_t*)(prev + 4);
	vp_syscall = prev_syscall + 1;
}

template<typename F = void(*)()>
class BadHook
{
private:
	static constexpr unsigned char jump_bytes[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };

	F src, dest, trampoline;
	int size;
	bool active;
	bool long_jmp;

	BadHook(F src, F dest, int size) : src(src), dest(dest), size(size), active(false), long_jmp(false)
	{
		long_jmp = abs(((int64_t)src + 5) - (int64_t)dest) > 0x7FFFFFFF;

		trampoline = (F)VirtualAlloc(NULL, size * 2, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(trampoline, src, size);
		uint64_t jumpback = (uint64_t)src + size;
		place_jmp_long((void*)((uint64_t)trampoline + size), (void*)jumpback, 14);

		hook();
	}

	void place_jmp_short(void* from, void* to, int size)
	{
		DWORD old;
		ProtectVirtualMemory(from, size, PAGE_EXECUTE_READWRITE, &old);
		*(uint8_t*)(from) = 0xE9;
		*(uint32_t*)((uint64_t)from + 1) = (uint32_t)(((uint64_t)to - (uint64_t)from) - 5);
		ProtectVirtualMemory(from, size, old, &old);
	}

	void place_jmp_long(void* from, void* to, int size)
	{
		DWORD old;
		ProtectVirtualMemory(from, size, PAGE_EXECUTE_READWRITE, &old);
		memcpy(from, jump_bytes, sizeof(jump_bytes));
		memcpy((void*)((uint64_t)from + sizeof(jump_bytes)), &to, 8);
		ProtectVirtualMemory(from, size, old, &old);
	}

public:
	~BadHook()
	{
		if (src != nullptr)
		{
			unhook();
			VirtualFree(trampoline, 0, MEM_RELEASE);
		}
	}

	BadHook(const BadHook&) = delete;
	BadHook& operator=(const BadHook&) = delete;

	BadHook(BadHook&& other) noexcept :
		src(std::exchange(other.src, nullptr)),
		dest(std::exchange(other.dest, nullptr)),
		trampoline(std::exchange(other.trampoline, nullptr)),
		size(std::exchange(other.size, 0)),
		active(std::exchange(other.active, false)),
		long_jmp(std::exchange(other.long_jmp, false))
	{}

	BadHook& operator=(BadHook&& other) noexcept
	{
		src = other.src;
		dest = other.dest;
		trampoline = other.trampoline;
		size = other.size;
		active = other.active;
		long_jmp = other.long_jmp;
		other.src = nullptr;
		return *this;
	}

	static BadHook hook_func(F func, F hook, int size = 0)
	{
		return BadHook(func, hook, size);
	}

	F get_orig()
	{
		return (F)trampoline;
	}

	void hook()
	{
		if (!active)
		{
			if (long_jmp)
				place_jmp_long(src, dest, size);
			else
				place_jmp_short(src, dest, size);
			active = true;
		}
	}

	void unhook()
	{
		if (active)
		{
			DWORD old;
			ProtectVirtualMemory(src, size, PAGE_EXECUTE_READWRITE, &old);
			memcpy(src, trampoline, size);
			ProtectVirtualMemory(src, size, old, &old);
			active = false;
		}
	}
};

template<typename T>
std::unique_ptr<BadHook<T>> make_hook(T func, T hook, int size = 0)
{
	return std::make_unique<BadHook<T>>(BadHook<T>::hook_func(func, hook, size));
}