#include <windows.h>
#include <stdint.h>

#define INJECT_ERROR_INJECT_FAILED -1
#define INJECT_ERROR_INVALID_PARAMS -2
#define INJECT_ERROR_OPEN_PROCESS_FAIL -3
#define INJECT_ERROR_UNLIKELY_FAIL -4

extern int inject_library_obf(HANDLE process, const wchar_t *dll, const char *create_remote_thread_obf, uint64_t obf1,
			      const char *write_process_memory_obf, uint64_t obf2, const char *virtual_alloc_ex_obf,
			      uint64_t obf3, const char *virtual_free_ex_obf, uint64_t obf4,
			      const char *load_library_w_obf, uint64_t obf5);

extern int inject_library_safe_obf(DWORD thread_id, const wchar_t *dll, const char *set_windows_hook_ex_obf,
				   uint64_t obf1);

/*
 * The obfuscated names of the functions the injection is made of, each paired with the key it is deobfuscated
 * with. They are given as arguments rather than being built in, so that a caller can supply its own scramble and
 * two binaries doing the same injection do not carry identical strings.
 *
 * These are the set that inject-helper uses, spelled out here for callers that have no reason to pick their own.
 * They deobfuscate to CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualFreeEx and LoadLibraryW, and
 * expand to the whole argument list rather than to single values, since that is the shape the call needs.
 */
#define INJECT_LIBRARY_OBF_ARGUMENTS                                                                  \
	"E}mo|d[cefubWk~bgk", 0x7c3371986918e8f6, "Rqbr`T{cnor{Bnlgwz", 0x81bf81adc9456b35,           \
		"]`~wrl`KeghiCt", 0xadc6a7b9acd73c9b, "Zh}{}agHzfd@{", 0x57135138eb08ff1c,            \
		"DnafGhj}l~sX", 0x350bfacdf81b2018

/* The equivalent for the SetWindowsHookEx based injection, which is the safe variant above. */
#define INJECT_LIBRARY_SAFE_OBF_ARGUMENTS "[bs^fbkmwuKfmfOvI", 0xEAD293602FCF9778ULL
