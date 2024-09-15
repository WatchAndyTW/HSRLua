#pragma once
#include <Windows.h>
#include <cstdint>

namespace util::pe
{
	const PIMAGE_SECTION_HEADER get_section_by_name(HMODULE base, const char* name)
	{
		const PIMAGE_DOS_HEADER hdos = (PIMAGE_DOS_HEADER)base;
		const PIMAGE_NT_HEADERS hpe = (PIMAGE_NT_HEADERS)((PBYTE)hdos + hdos->e_lfanew);
		const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(hpe);
		for (int i = 0; i < hpe->FileHeader.NumberOfSections; i++)
		{
			if (strcmp((const char*)sections[i].Name, name) == 0)
			{
				return &sections[i];
			}
		}
		return NULL;
	}

    const int get_module_timestamp(HMODULE base) {
        // Access the DOS header
        const PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "Invalid DOS signature." << std::endl;
            return 0;
        }

        // Access the NT headers
        const PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "Invalid NT signature." << std::endl;
            return 0;
        }

        int timestamp = static_cast<int>(ntHeaders->FileHeader.TimeDateStamp);
        return timestamp;
    }
}