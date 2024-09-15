#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <cstdio>
#include <cstdint>
#include <sstream>
#include <optional>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <MinHook.h>

#include "scanner.hpp"
#include "pe.hpp"
#include "util.hpp"
#include "hook.hpp"

namespace fs = std::filesystem;
using namespace std;

struct lua_State;

lua_State* hsr_L;
HMODULE xluau;
HMODULE custom_xluau;

typedef int (WINAPI* pfn_load)(lua_State*, const char*, const char*, size_t, int);
typedef int (WINAPI* pfn_pcall)(lua_State*, int, int, int);
typedef int (WINAPI* pfn_settop)(lua_State*, int);
typedef const char* (WINAPI* pfn_compile)(const char*, size_t, const void*, size_t*);
typedef lua_State* (WINAPI* pfn_newstate)();
typedef int (WINAPI* pfn_tolstring)(lua_State*, int, size_t*);
typedef int (WINAPI* pfn_loadbuffer)(lua_State*, const char*, size_t, const char*);

pfn_load luau_load = NULL;
pfn_pcall lua_pcall = NULL;
pfn_settop lua_settop = NULL;
pfn_compile luau_compile = NULL;
pfn_newstate luaL_newstate = NULL;
pfn_tolstring lua_tolstring = NULL;
pfn_loadbuffer xluaL_loadbuffer = NULL;

void get_hsr_L(lua_State* L)
{
    hsr_L = L;

    // Init function address
    lua_settop = (pfn_settop)GetProcAddress(xluau, "lua_settop");
    lua_tolstring = (pfn_tolstring)GetProcAddress(xluau, "lua_tolstring");
    xluaL_loadbuffer = (pfn_loadbuffer)GetProcAddress(xluau, "xluaL_loadbuffer");
    lua_pcall = (pfn_pcall)GetProcAddress(xluau, "lua_pcall");
    luau_compile = (pfn_compile)((FARPROC)((uintptr_t)custom_xluau + 0xAAFA0));

    util::log("Waiting for Lua...\n");

    while (hsr_L != 0) {
        util::log("L: %p\n", hsr_L);
        break;
    }
}

const char* compile(string script)
{
    size_t bytecode_size = 0;
    auto compiled = luau_compile(script.c_str(), script.length(), nullptr, &bytecode_size);

    return compiled;
}

std::optional<fs::path> get_scripts_folder(const char* folder_name)
{
    auto mod_dir = util::this_dir();
    if (!mod_dir)
        return std::nullopt;

    auto scripts_path = mod_dir.value() / folder_name;
    if (fs::is_directory(scripts_path))
        return scripts_path;

    util::log("%s folder not found\n", folder_name);
    return std::nullopt;
}

void exec(const char* compiled)
{
    int ret = xluaL_loadbuffer(hsr_L, compiled, strlen(compiled), "HSRLua");
    if (ret != 0)
    {
        util::log("Loading failed(%i)\n", ret);
        util::log("%s\n", lua_tolstring(hsr_L, 1, NULL));
        lua_settop(hsr_L, 1);
        return;
    }

    ret = lua_pcall(hsr_L, 0, 0, 0);
    if (ret != 0)
    {
        util::log("Execution failed(%i)\n", ret);
        util::log("%s\n", lua_tolstring(hsr_L, 1, NULL));
        lua_settop(hsr_L, 1);
    }
}

void load_lua_file(lua_State* L, const fs::path& file)
{
    auto name = file.filename().string();
    util::log("Loading %s\n", name.c_str());

    auto script = util::read_whole_file(file);
    if (!script)
    {
        util::log("Failed reading file %s\n", name.c_str());
        return;
    }

    auto compiled = compile(script.value());
    if (!compiled)
        return;

    exec(compiled);
}

void load_luas_from_dir(lua_State* L, const fs::path& dir)
{
    for (const auto& entry : fs::directory_iterator{ dir })
    {
        if (entry.is_regular_file() && entry.path().extension() == ".lua")
        {
            load_lua_file(L, entry);
        }
    }
}

int WINAPI luau_load_replacement(lua_State* L, const char* chunkname, const char* data, size_t size, int env) {
    string chunkname_str(chunkname);

    if (chunkname_str == "@BakedLua/MainEntry.bytes")
    {
        get_hsr_L(L);
    }
    else if (chunkname_str == "@BakedLua/Ui/GameStartup/LoginAgeHint.bytes")
    {
        auto dir = get_scripts_folder("AutoLoad");
        if (!dir) return luau_load(L, chunkname, data, size, env);
        for (const auto& entry : fs::directory_iterator{ dir.value() })
        {
            if (entry.is_regular_file() && entry.path().extension() == ".lua")
            {
                util::log("Loading %s\n", entry.path().filename().string().c_str());
                auto file = dir.value() / entry;
                auto script = util::read_whole_file(file);
                if (!script)
                {
                    util::log("Failed reading file %s\n", entry.path().filename().string().c_str());
                    continue;
                }
                auto compiled = compile(script.value());

                luau_load(L, chunkname, compiled, strlen(compiled), 0);
                lua_pcall(L, 0, 0, 0);
            }
        }
    }
    
    return luau_load(L, chunkname, data, size, env);
}

void command_loop(lua_State* L, fs::path& scripts)
{
    util::log("Type 'loadall' to load all scripts\n");
    util::log("Type 'load <filename> ...' to load specific scripts\n");
    util::log("WARNING: If you are executing scripts with Reflection, please place the scripts into AutoLoad folder\n");

    while (true)
    {
        std::string input;
        std::getline(std::cin, input);
        auto cmd = util::split(input, ' ');
        if (cmd.empty())
            continue;
        auto nargs = cmd.size() - 1;

        if (cmd[0] == "loadall")
        {
            load_luas_from_dir(L, scripts);
        }
        else if (cmd[0] == "load")
        {
            for (int i = 0; i < nargs; i++)
            {
                auto file = scripts / cmd[i+1];
                file.replace_extension(".lua");
                if (fs::is_regular_file(file))
                    load_lua_file(L, file);
                else
                    util::log("File %s not found\n", file.string().c_str());
            }
        }
        else
            util::log("Invalid command!\n");
    }
}

DWORD start(LPVOID)
{
    AllocConsole();
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    util::log("HSRLua by WatchAndyTW, based on GILua by azzu\n");

    // Check if folders exist
    auto dir = get_scripts_folder("Scripts");
    if (!dir)
        return 0;
    if (!get_scripts_folder("AutoLoad"))
        return 0;

    // Wait until xluau.dll initialized
    while (true)
    {
        if (xluau = GetModuleHandle(L"xluau.dll"))
            break;

        Sleep(50);
    }

    // Load custom xluau library for bytecode compiling
    custom_xluau = LoadLibraryA("xluau.x64d.dll");

    // MinHook initialize
    if (MH_Initialize() == MB_OK)
    {
        // Hook luau_load
        auto luau_load_addr = GetProcAddress(xluau, "luau_load");
        auto luau_load_ptarget = (pfn_load)luau_load_addr;
        MH_CreateHook(reinterpret_cast<LPVOID>(luau_load_ptarget), reinterpret_cast<LPVOID>(&luau_load_replacement), reinterpret_cast<LPVOID*>(&luau_load));
        MH_EnableHook(reinterpret_cast<LPVOID>(luau_load_ptarget));
    }

    // Create new lua state
    luaL_newstate = (pfn_newstate)GetProcAddress(xluau, "luaL_newstate");
    auto state = luaL_newstate();

    // rsapatch breaks input, restore input mode
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),
        ENABLE_INSERT_MODE | ENABLE_EXTENDED_FLAGS |
        ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE |
        ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT
        );

    command_loop(state, dir.value());

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        CloseHandle(CreateThread(NULL, 0, &start, NULL, NULL, NULL));
    return TRUE;
}