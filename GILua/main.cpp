#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <cstdio>
#include <cstdint>
#include <sstream>
#include <optional>
#include <iostream>
#include <fstream>
#include <filesystem>

#include "lua/lua.hpp"

lua_State* gi_L;
HMODULE xlua;

using pfn_loadbuffer = int (*)(lua_State*, const char*, size_t, const char*);
pfn_loadbuffer* pp_loadbuffer;
int xluaL_loadbuffer_hook(lua_State* L, const char* chunk, size_t sz, const char* chunkname)
{
    gi_L = L;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"xlua", &xlua);
    *pp_loadbuffer = (pfn_loadbuffer)GetProcAddress(xlua, "xluaL_loadbuffer");
    return (*pp_loadbuffer)(L, chunk, sz, chunkname);
}

void get_gi_L()
{
    printf("Waiting...\n");

    uint64_t ua = 0;
    while ((ua = (uint64_t)GetModuleHandle(L"UserAssembly.dll")) == 0)
        Sleep(50);

    pp_loadbuffer = (pfn_loadbuffer*)(ua + 0xC6DA240);
    *pp_loadbuffer = xluaL_loadbuffer_hook;

    while (!gi_L)
        Sleep(50);

    printf("L: %p\n", gi_L);
}

std::optional<std::string> compile(lua_State* L, const char* script)
{
    std::ostringstream compiled_script;

    auto writer = [](lua_State* L, const void* p, size_t sz, void* ud) -> int
    {
        auto out = (std::ostringstream*)ud;
        out->write((const char*)p, sz);
        return 0;
    };

    auto ret = luaL_loadstring(L, script);
    if (ret != 0)
    {
        printf("compilation failed(%i)\n", ret);
        printf("%s\n", lua_tolstring(L, 1, NULL));
        lua_pop(L, 1);
        return std::nullopt;
    }

    ret = lua_dump(L, writer, &compiled_script, 0);
    if (ret != 0)
    {
        printf("lua_dump failed(%i)\n", ret);
        return std::nullopt;
    }

    lua_pop(L, 1);
    return compiled_script.str();
}

void exec(std::string compiled)
{
    using pfn_pcall = int (*)(void* L, int nargs, int nresults, int errfunc);
    static auto xlua_pcall = (pfn_pcall)GetProcAddress(xlua, "lua_pcall");
    static auto xluaL_loadbuffer = (pfn_loadbuffer)GetProcAddress(xlua, "xluaL_loadbuffer");

    int ret = xluaL_loadbuffer(gi_L, compiled.c_str(), compiled.length(), "GILua");
    if (ret != 0)
    {
        printf("loading failed(%i)\n", ret);
        printf("%s\n", lua_tolstring(gi_L, 1, NULL));
        lua_pop(gi_L, 1);
        return;
    }

    ret = xlua_pcall(gi_L, 0, 0, 0);
    if (ret != 0)
    {
        printf("execution failed(%i)\n", ret);
        printf("%s\n", lua_tolstring(gi_L, 1, NULL));
        lua_pop(gi_L, 1);
    }
}

std::optional<std::string> read_whole_file(const std::filesystem::path& file)
try
{
    std::stringstream buf;
    std::ifstream ifs(file);
    if (!ifs.is_open())
        return std::nullopt;
    ifs.exceptions(std::ios::failbit);
    buf << ifs.rdbuf();
    return buf.str();
}
catch (const std::ios::failure&)
{
    return std::nullopt;
}

void load_luas_from_dir(lua_State* L, const std::filesystem::path& dir)
{
    for (const auto& entry : std::filesystem::directory_iterator{ dir })
    {
        if (entry.is_regular_file() && entry.path().extension() == ".lua")
        {
            auto name = entry.path().filename().string();
            printf("loading %s\n", name.c_str());

            auto script = read_whole_file(entry.path());
            if (!script)
            {
                printf("Failed reading file %s\n", name.c_str());
                continue;
            }

            auto compiled = compile(L, script.value().c_str());
            if (!compiled)
                continue;

            exec(compiled.value());
        }
    }
}

std::optional<std::filesystem::path> get_scripts_folder(HMODULE this_mod)
{
    TCHAR path[MAX_PATH]{};
    if (!GetModuleFileName(this_mod, path, MAX_PATH))
    {
        printf("GetModuleFileName failed (%i)\n", GetLastError());
        return std::nullopt;
    }

    auto scripts_path = std::filesystem::path(path).remove_filename() / "Scripts";
    if (std::filesystem::exists(scripts_path) && std::filesystem::is_directory(scripts_path))
        return scripts_path;

    printf("Scripts folder not found\n");
    return std::nullopt;
}

DWORD start(LPVOID this_mod)
{
    AllocConsole();
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    //freopen("CONOUT$", "w", stderr);

    printf("GILua by azzu\n");

    auto dir_opt = get_scripts_folder((HMODULE)this_mod);
    if (!dir_opt)
        return 0;
    auto dir = dir_opt.value();

    get_gi_L();

    printf("Type 'load' to load all scripts\n");

    auto state = luaL_newstate();
    while (true)
    {
        std::string input;
        std::getline(std::cin, input);
        if (input == "load")
            load_luas_from_dir(state, dir);
        else
            printf("Invalid command!\n");
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        CloseHandle(CreateThread(NULL, 0, &start, hinstDLL, NULL, NULL));
    return TRUE;
}