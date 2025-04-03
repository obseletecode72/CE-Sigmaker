#include "loader.h"
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <windows.h>
#include <cstdlib>
#include <fstream>
#include <TlHelp32.h>
static CE_EXPORTED_FUNCTIONS exports;
static CE_MEMORY_VIEW_PLUGIN_INIT memory_view_tab;
static CE_DISASSEMBLER_CONTEXT_INIT disassembler_context_option;
static CE_DISASSEMBLER_CONTEXT_INIT search_pattern_context_option;
void set_clipboard(const std::string& str) {
	OpenClipboard(nullptr);
	EmptyClipboard();
	HGLOBAL buf = GlobalAlloc(GMEM_MOVEABLE, str.size() + 1);
	if (!buf) { CloseClipboard(); return; }
	char* p = reinterpret_cast<char*>(GlobalLock(buf));
	std::memcpy(p, str.c_str(), str.size() + 1);
	GlobalUnlock(buf);
	SetClipboardData(CF_TEXT, buf);
	CloseClipboard();
	GlobalFree(buf);
}
std::vector<int> parsePattern(const std::string& pattern) {
	std::istringstream iss(pattern);
	std::vector<int> bytes;
	std::string token;
	while (iss >> token) {
		if (token == "?" || token == "??")
			bytes.push_back(-1);
		else
			bytes.push_back(std::strtol(token.c_str(), nullptr, 16));
	}
	return bytes;
}
bool matchPattern(const unsigned char* data, size_t dataSize, const std::vector<int>& pattern) {
	if (dataSize < pattern.size()) return false;
	for (size_t i = 0; i < pattern.size(); i++) {
		if (pattern[i] != -1 && data[i] != static_cast<unsigned char>(pattern[i]))
			return false;
	}
	return true;
}
bool getModuleRange(HANDLE handle, uintptr_t selected_address, uintptr_t& moduleBase, size_t& moduleSize) {
	DWORD procId = GetProcessId(handle);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procId);
	if (hSnap == INVALID_HANDLE_VALUE)
		return false;
	MODULEENTRY32 me;
	me.dwSize = sizeof(me);
	if (Module32First(hSnap, &me)) {
		do {
			uintptr_t modBase = reinterpret_cast<uintptr_t>(me.modBaseAddr);
			size_t modSize = static_cast<size_t>(me.modBaseSize);
			if (selected_address >= modBase && selected_address < modBase + modSize) {
				moduleBase = modBase;
				moduleSize = modSize;
				CloseHandle(hSnap);
				return true;
			}
		} while (Module32Next(hSnap, &me));
	}
	CloseHandle(hSnap);
	return false;
}
std::vector<uintptr_t> getPatternOccurrencesAddresses(HANDLE handle, const std::string& pattern, uintptr_t moduleBase, size_t moduleSize) {
	std::vector<uintptr_t> occurrences;
	std::vector<int> pat = parsePattern(pattern);
	uintptr_t addr = moduleBase;
	uintptr_t moduleEnd = moduleBase + moduleSize;
	while (addr < moduleEnd) {
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
			break;
		if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY))) {
			size_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
			if (regionEnd > moduleEnd)
				regionEnd = moduleEnd;
			std::vector<unsigned char> buffer(regionEnd - reinterpret_cast<uintptr_t>(mbi.BaseAddress));
			SIZE_T bytesRead;
			if (ReadProcessMemory(handle, mbi.BaseAddress, buffer.data(), regionEnd - reinterpret_cast<uintptr_t>(mbi.BaseAddress), &bytesRead)) {
				for (size_t i = 0; i + pat.size() <= bytesRead; i++) {
					if (matchPattern(buffer.data() + i, pat.size(), pat))
						occurrences.push_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + i);
				}
			}
		}
		addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
	}
	return occurrences;
}
BOOL CE_CONV on_makesig(uintptr_t* selected_address) {
	auto handle = *exports.OpenedProcessHandle;
	uintptr_t moduleBase = 0;
	size_t moduleSize = 0;
	if (!getModuleRange(handle, *selected_address, moduleBase, moduleSize)) {
		exports.ShowMessage("Module not found for selected address");
		return false;
	}
	const size_t maxSigBytes = 100;
	uintptr_t addr = *selected_address;
	std::vector<std::string> tokens;
	size_t totalBytes = 0;
	bool uniqueFound = false;
	std::string candidate;
	while (totalBytes < maxSigBytes) {
		unsigned char buffer[32];
		SIZE_T bytesRead;
		if (!ReadProcessMemory(handle, reinterpret_cast<void*>(addr), buffer, sizeof(buffer), &bytesRead) || bytesRead == 0)
			break;
		HDE hs;
		HDE_DISASM(buffer, &hs);
		if (totalBytes + hs.len > maxSigBytes)
			break;
		for (unsigned int i = 0; i < hs.len; i++) {
			std::ostringstream oss;
			if (hs.opcode == 0xE8 || hs.opcode == 0xE9)
				oss << "?";
			else
				oss << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]);
			tokens.push_back(oss.str());
		}
		totalBytes += hs.len;
		for (size_t prefix = 1; prefix <= tokens.size(); prefix++) {
			std::ostringstream patternStream;
			for (size_t j = 0; j < prefix; j++) {
				if (j > 0)
					patternStream << " ";
				patternStream << tokens[j];
			}
			std::string patternPrefix = patternStream.str();
			std::vector<uintptr_t> occurrences = getPatternOccurrencesAddresses(handle, patternPrefix, moduleBase, moduleSize);
			if (occurrences.size() == 1) {
				candidate = patternPrefix;
				uniqueFound = true;
				break;
			}
		}
		if (uniqueFound)
			break;
		addr += hs.len;
	}
	if (!uniqueFound) {
		exports.ShowMessage("Unique signature not found up to maximum size");
		return false;
	}
	set_clipboard(candidate);
	exports.ShowMessage("Copied unique signature to clipboard!");
	return true;
}
BOOL CE_CONV on_searchpattern(uintptr_t* selected_address) {
	auto handle = *exports.OpenedProcessHandle;
	uintptr_t moduleBase = 0;
	size_t moduleSize = 0;
	if (!getModuleRange(handle, *selected_address, moduleBase, moduleSize)) {
		exports.ShowMessage("Module not found for selected address");
		return false;
	}
	const size_t maxSigBytes = 100;
	uintptr_t addr = *selected_address;
	std::vector<std::string> tokens;
	size_t totalBytes = 0;
	bool found = false;
	uintptr_t foundAddress = 0;
	while (totalBytes < maxSigBytes) {
		unsigned char buffer[32];
		SIZE_T bytesRead;
		if (!ReadProcessMemory(handle, reinterpret_cast<void*>(addr), buffer, sizeof(buffer), &bytesRead) || bytesRead == 0)
			break;
		HDE hs;
		HDE_DISASM(buffer, &hs);
		if (totalBytes + hs.len > maxSigBytes)
			break;
		for (unsigned int i = 0; i < hs.len; i++) {
			std::ostringstream oss;
			if (hs.opcode == 0xE8 || hs.opcode == 0xE9)
				oss << "?";
			else
				oss << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]);
			tokens.push_back(oss.str());
		}
		totalBytes += hs.len;
		for (size_t prefix = 1; prefix <= tokens.size(); prefix++) {
			std::ostringstream patternStream;
			for (size_t j = 0; j < prefix; j++) {
				if (j > 0)
					patternStream << " ";
				patternStream << tokens[j];
			}
			std::string patternPrefix = patternStream.str();
			std::vector<uintptr_t> occurrences = getPatternOccurrencesAddresses(handle, patternPrefix, moduleBase, moduleSize);
			if (occurrences.size() == 1) {
				found = true;
				foundAddress = occurrences[0];
				break;
			}
		}
		if (found)
			break;
		addr += hs.len;
	}
	if (!found) {
		exports.ShowMessage("Unique pattern not found up to maximum size");
		return false;
	}
	std::ostringstream oss;
	oss << "0x" << std::hex << foundAddress;
	set_clipboard(oss.str());
	exports.ShowMessage("Copied address to clipboard!");
	return true;
}
BOOL CE_CONV on_rightclick(uintptr_t selected_address, const char** name_address, BOOL* show) {
	return true;
}
BOOL CE_CONV on_settings_click(uintptr_t* disassembler_address, uintptr_t* selected_disassembler_address, uintptr_t* hexview_address) {
	return TRUE;
}
BOOL CE_CONV CEPlugin_GetVersion(CE_PLUGIN_VERSION* version, int version_size) {
	version->plugin_name = "SigMaker";
	version->version = 1.0;
	return sizeof(CE_PLUGIN_VERSION) == version_size;
}
BOOL CE_CONV CEPlugin_InitializePlugin(CE_EXPORTED_FUNCTIONS* ef, int pluginid) {
	exports = *ef;
	disassembler_context_option.name = "SigMaker: Create signature";
	disassembler_context_option.callback_routine = &on_makesig;
	disassembler_context_option.callback_routine_onpopup = &on_rightclick;
	exports.RegisterFunction(pluginid, CE_PLUGIN_TYPE_DISASSEMBLER_CONTEXT, &disassembler_context_option);
	search_pattern_context_option.name = "SigMaker: Search Pattern";
	search_pattern_context_option.callback_routine = &on_searchpattern;
	search_pattern_context_option.callback_routine_onpopup = &on_rightclick;
	exports.RegisterFunction(pluginid, CE_PLUGIN_TYPE_DISASSEMBLER_CONTEXT, &search_pattern_context_option);
	return true;
}
BOOL CE_CONV CEPlugin_DisablePlugin() {
	return true;
}
