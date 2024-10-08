// ReSharper disable CppCStyleCast
#define PHNT_VERSION PHNT_THRESHOLD
#define _NO_CRT_STDIO_INLINE
#define _CRT_SECURE_NO_WARNINGS
#define _CORECRT_BUILD
#include <phnt_windows.h>

#include <phnt.h>

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <type_traits>

#include <tiny-json.h>

#undef RTL_CONSTANT_STRING
#define RTL_CONSTANT_STRING(s)                                                                       \
  {                                                                                                  \
    sizeof(s) - sizeof((s)[0]),                                                                      \
      sizeof(s),                                                                                     \
      (std::add_pointer_t<std::remove_const_t<std::remove_pointer_t<std::decay_t<decltype(s)>>>>)(s) \
  }

_ACRTIMP _CRT_HYBRIDPATCHABLE void __cdecl free(
  _Pre_maybenull_ _Post_invalid_ void* _Block
) {
  RtlFreeHeap(RtlProcessHeap(), 0, _Block);
}

_Check_return_ _Ret_maybenull_ _Post_writable_byte_size_(_Size)

_ACRTIMP _CRTALLOCATOR _CRT_JIT_INTRINSIC _CRTRESTRICT _CRT_HYBRIDPATCHABLE void* __cdecl malloc(
  _In_ _CRT_GUARDOVERFLOW size_t _Size
) {
  return RtlAllocateHeap(RtlProcessHeap(), 0, _Size);
}

using PPS_POST_PROCESS_INIT_ROUTINE = VOID(NTAPI*)(VOID);

static PPS_POST_PROCESS_INIT_ROUTINE s_original_post_init;
static PVOID s_dll_notification_cookie;

inline int vformatted_message_box(HWND hwnd, LPCSTR caption, UINT type, LPCSTR fmt, va_list args) {
  char text[4096];
  vsprintf_s(text, std::size(text), fmt, args);
  return MessageBoxA(hwnd, text, caption, type);
}

inline int formatted_message_box(HWND hwnd, LPCSTR caption, UINT type, LPCSTR fmt, ...) {
  va_list args;
  va_start(args, fmt);
  auto result = vformatted_message_box(hwnd, caption, type, fmt, args);
  va_end(args);
  return result;
}

[[noreturn]] inline void fail(LPCSTR fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vformatted_message_box(nullptr, "Patcher failed!", MB_OK | MB_ICONERROR, fmt, args);
  va_end(args);
  NtTerminateProcess(NtCurrentProcess(), STATUS_UNSUCCESSFUL);
  __debugbreak();
}

struct patch_entry {
  const char* const* modules{};
  size_t modules_length{};

  const uint16_t* pattern{};
  size_t pattern_length{};

  const uint8_t* replacement{};
  size_t replacement_length{};

  size_t min_matches = 1;
  size_t max_matches = 1;

  bool on_initialize = false;
  bool on_process_initialized = false;
  bool on_before_dllmain = false;

  bool is_code = true;
  bool allowed_to_fail = false;

  bool multishot = false;
  bool done = false;

  patch_entry* next{};
};

enum class patch_check_reason {
  initialize,
  process_initialized,
  ldr_callback
};

patch_entry* s_patches_head{};

NTSTATUS super_memcpy(void* dst, const void* src, size_t size) {
  ULONG old_protect{};
  PVOID dst_copy = dst;
  SIZE_T size_copy = size;
  auto status = NtProtectVirtualMemory(
    NtCurrentProcess(),
    &dst_copy,
    &size_copy,
    PAGE_EXECUTE_READWRITE,
    &old_protect
  );
  if (!NT_SUCCESS(status))
    return status;
  SIZE_T written{};
  status = NtWriteVirtualMemory(
    NtCurrentProcess(),
    dst,
    (PVOID)src,
    size,
    &written
  );
  if (!NT_SUCCESS(status))
    return status;
  // we don't care about the result
  NtProtectVirtualMemory(
    NtCurrentProcess(),
    &dst_copy,
    &size_copy,
    old_protect,
    &old_protect
  );
  return STATUS_SUCCESS;
}

void apply_patch_entry(PVOID base, PCUNICODE_STRING basename, patch_entry* entry) {
  size_t patch_count = 0;
  const auto nth = RtlImageNtHeader(base);
  const auto sections_count = nth->FileHeader.NumberOfSections;
  const auto sections = (PIMAGE_SECTION_HEADER)(nth + 1);
  for (auto i = 0; i < sections_count; i++) {
    const auto& section = sections[i];
    if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE) ^ entry->is_code) {
      const auto begin = (uint8_t*)base + section.VirtualAddress;
      const auto end = begin + section.Misc.VirtualSize;
      uint8_t* it = begin;
      while ((it = std::search(
                it,
                end,
                entry->pattern,
                entry->pattern + entry->pattern_length,
                [](uint8_t curr, uint16_t pat) { return (curr & pat >> 8) == (pat & 0xFF); }
              ))
             != end) {
        if (NT_SUCCESS(super_memcpy(it, entry->replacement, entry->replacement_length)))
          ++patch_count;
        ++it;
      }
    }
  }
  bool failed = false;
  if (patch_count < entry->min_matches || patch_count > entry->max_matches)
    failed = true;

  if (failed && !entry->allowed_to_fail)
    fail("Failed patching %wZ!", basename);

  if (!failed)
    entry->done = true;
}

void patch_module(patch_check_reason reason, PCUNICODE_STRING basename, PVOID base) {
  for (auto entry = s_patches_head; entry; entry = entry->next) {
    if (reason == patch_check_reason::initialize && !entry->on_initialize)
      continue;
    if (reason == patch_check_reason::process_initialized && !entry->on_process_initialized)
      continue;
    if (reason == patch_check_reason::ldr_callback && !entry->on_before_dllmain)
      continue;
    if (!entry->multishot && entry->done)
      continue;
    bool any_matches = false;
    for (auto module = entry->modules; module < entry->modules + entry->modules_length; ++module) {
      bool matches = true;
      for (size_t i = 0; i < basename->Length / 2; ++i) {
        if (tolower(basename->Buffer[i]) != tolower((*module)[i])) {
          matches = false;
          break;
        }
      }
      if (matches) {
        any_matches = true;
        break;
      }
    }

    if (any_matches) {
      apply_patch_entry(base, basename, entry);
    }
  }
}

void iterate_modules(patch_check_reason reason) {
  LdrEnumerateLoadedModules(
    FALSE,
    [](_In_ PLDR_DATA_TABLE_ENTRY entry, _In_ PVOID ctx, _Out_ BOOLEAN* stop) {
      const auto reason = (patch_check_reason)(uintptr_t)ctx;
      const auto base = entry->DllBase;
      patch_module(reason, &entry->BaseDllName, base);
      if (base == NtCurrentPeb()->ImageBaseAddress) {
        UNICODE_STRING name = RTL_CONSTANT_STRING(L"{exe}");
        patch_module(reason, &name, base);
      }
    },
    (PVOID)(uintptr_t)reason
  );
}

VOID NTAPI post_process_init() {
  iterate_modules(patch_check_reason::process_initialized);
  NtCurrentPeb()->PostProcessInitRoutine = s_original_post_init;
  if (s_original_post_init)
    s_original_post_init();
}

VOID NTAPI dll_notification(
  _In_ ULONG notification_reason,
  _In_ PCLDR_DLL_NOTIFICATION_DATA notification_data,
  _In_opt_ PVOID context
) {
  if (notification_reason != LDR_DLL_NOTIFICATION_REASON_LOADED)
    return;
  patch_module(patch_check_reason::ldr_callback, notification_data->Loaded.BaseDllName, notification_data->Loaded.DllBase);
}

PVOID get_export(PVOID mod, PCSTR export_name) {
  ANSI_STRING ansi;
  RtlInitAnsiString(&ansi, export_name);
  PVOID address{};
  LdrGetProcedureAddress(mod, &ansi, 0, &address);
  return address;
}

#define GET_EXPORT(name) ((decltype(&(name)))get_export(ntdll, #name))

class jsonParser : jsonPool_t {
  struct jsonLink : json_t {
    jsonLink* next;
  };

  static json_t* alloc_fn(jsonPool_t* pool) {
    const auto list_pool = (jsonParser*)pool;
    return list_pool->alloc();
  }

  json_t* alloc() {
    const auto new_link = (jsonLink*)malloc(sizeof(jsonLink));
    new_link->next = _list;
    _list = new_link;
    return new_link;
  }

  void free_all() {
    while (const auto link = _list) {
      _list = link->next;
      free(link);
    }
  }

  jsonLink* _list{};
  char* _str{};
  const json_t* _root{};

public:
  jsonParser()
      : jsonPool_t{&alloc_fn, &alloc_fn} {}

  explicit jsonParser(char* str)
      : jsonPool_t{&alloc_fn, &alloc_fn}
      , _str{str} {
    _root = json_createWithPool(str, this);
  }

  ~jsonParser() {
    free_all();
    free(_str);
  }

  jsonParser(const jsonParser&) = delete;
  jsonParser(jsonParser&&) = delete;
  jsonParser& operator=(const jsonParser&) = delete;
  jsonParser& operator=(jsonParser&&) = delete;

  void parse(char* str) {
    _str = str;
    free_all();
    _root = json_createWithPool(str, this);
  }

  [[nodiscard]] const json_t* root() const { return _root; }
};

char* get_config() {
  LDR_RESOURCE_INFO res_info{(UINT_PTR)RT_RCDATA};
  PIMAGE_RESOURCE_DATA_ENTRY res_data_entry{};
  LdrFindResource_U(&__ImageBase, &res_info, RESOURCE_TYPE_LEVEL, &res_data_entry);
  if (res_data_entry) {
    PVOID res_data{};
    ULONG res_data_size{};
    LdrAccessResource(&__ImageBase, res_data_entry, &res_data, &res_data_size);
    if (res_data) {
      const auto config = (char*)malloc(res_data_size + 1);
      config[res_data_size] = 0;
      memcpy(config, res_data, res_data_size);
      return config;
    }
  }

  PLDR_DATA_TABLE_ENTRY ldr_entry{};
  LdrFindEntryForAddress(&__ImageBase, &ldr_entry);
  if (ldr_entry) {
    const auto& dll_path = ldr_entry->FullDllName;
    UNICODE_STRING config_path{};
    ULONG config_path_alloc_size = dll_path.Length + sizeof(L"\\??\\patches.json");
    RtlInitEmptyUnicodeString(
      &config_path,
      (wchar_t*)malloc(config_path_alloc_size),
      config_path_alloc_size
    );
    RtlAppendUnicodeToString(&config_path, L"\\??\\");
    RtlAppendUnicodeStringToString(&config_path, &dll_path);
    UNICODE_STRING charset = RTL_CONSTANT_STRING(L"\\");
    USHORT prefix_length{};
    RtlFindCharInUnicodeString(
      RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END,
      &config_path,
      &charset,
      &prefix_length
    );
    config_path.Length = prefix_length + sizeof(WCHAR);
    RtlAppendUnicodeToString(&config_path, L"patches.json");

    HANDLE file{};
    OBJECT_ATTRIBUTES attr{};
    InitializeObjectAttributes(&attr, &config_path, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK io_status{};
    auto status = NtOpenFile(
      &file,
      FILE_GENERIC_READ,
      &attr,
      &io_status,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      FILE_SYNCHRONOUS_IO_NONALERT
    );
    RtlFreeUnicodeString(&config_path);
    if (NT_SUCCESS(status)) {
      FILE_STANDARD_INFORMATION standard_info{};
      status = NtQueryInformationFile(
        file,
        &io_status,
        &standard_info,
        sizeof(standard_info),
        FileStandardInformation
      );
      if (NT_SUCCESS(status)) {
        const auto len = standard_info.EndOfFile.QuadPart;
        const auto config = (char*)malloc(len + 1);
        config[len] = 0;
        status = NtReadFile(
          file,
          nullptr,
          nullptr,
          nullptr,
          &io_status,
          config,
          len,
          nullptr,
          nullptr
        );
        if (NT_SUCCESS(status)) {
          NtClose(file);
          return config;
        }
        free(config);
      }
      NtClose(file);
    }
  }
  return nullptr;
}

template <typename T>
bool json_tryGetProperty(const json_t* json, const char* property, T& t) {
  const auto prop = json_getProperty(json, property);
  if (!prop)
    return true; // user **intended** this to be default
  const auto type = json_getType(prop);
  if constexpr (std::is_same_v<std::decay_t<T>, bool>) {
    return type == JSON_BOOLEAN && (t = json_getBoolean(prop), true);
  } else if constexpr (std::is_same_v<std::decay_t<T>, const char*>) {
    return type == JSON_TEXT && (t = json_getValue(prop), true);
  } else if constexpr (std::is_integral_v<std::decay_t<T>>) {
    return type == JSON_INTEGER && (t = (T)strtol(json_getValue(prop), nullptr, 10), true);
  } else if constexpr (std::is_floating_point_v<std::decay_t<T>>) {
    return type == JSON_REAL && (t = (T)json_getReal(prop), true);
  } else {
    static_assert("Wrong type!");
  }
  return false;
}

size_t json_getChildrenCount(const json_t* json) {
  size_t count = 0;
  for (auto it = json_getChild(json); it; it = json_getSibling(it))
    ++count;
  return count;
}

uint8_t unhex(char c) {
#define TEST_RANGE(c, a, b, offset)                         \
  if (uint8_t(c) >= uint8_t(a) && uint8_t(c) <= uint8_t(b)) \
  return uint8_t(c) - uint8_t(a) + (offset)

  TEST_RANGE(c, '0', '9', 0x0);
  TEST_RANGE(c, 'a', 'f', 0xa);
  TEST_RANGE(c, 'A', 'F', 0xA);

#undef TEST_RANGE

  return 0xFF;
};

bool parse_pattern(const char* str, const uint16_t** pattern, size_t* pattern_length) {
  *pattern = nullptr;
  *pattern_length = 0;

  const auto str_len = strlen(str);
  const auto pat = (uint16_t*)malloc(str_len);
  bool success = true;
  size_t len = 0;

  // advanced pattern
  if (str[0] == '#') {
    if ((str_len - 1) % 4 != 0)
      success = false;
    else {
      for (auto i = 1; i < str_len; i += 4) {
        const auto nibble1 = unhex(str[i]);
        const auto nibble2 = unhex(str[i + 1]);
        const auto nibble3 = unhex(str[i + 2]);
        const auto nibble4 = unhex(str[i + 3]);
        if (nibble1 == 0xFF || nibble2 == 0xFF || nibble3 == 0xFF || nibble4 == 0xFF) {
          success = false;
        } else {
          pat[len++] = (uint16_t)(nibble1 << 12 | nibble2 << 8 | nibble3 << 4 | nibble4);
        }
      }
    }
  } else {
    char lastc = ' ';
    while (auto c = *str++) {
      if (c == ' ') {
        (void)0;
      } else if (c == '?') {
        if (lastc != '?')
          pat[len++] = 0x0000;
        else
          c = ' '; // every second question mark counts as nothing
      } else if (lastc != ' ') {
        const auto nibble1 = unhex(lastc);
        const auto nibble2 = unhex(c);
        if (nibble1 == 0xFF || nibble2 == 0xFF) {
          success = false;
          break;
        }
        pat[len++] = (uint16_t)(0xFF00 | nibble1 << 4 | nibble2);
        c = ' ';
      }

      lastc = c;
    }
    if (lastc != ' ' && lastc != '?')
      success = false;
  }

  if (success) {
    *pattern = pat;
    *pattern_length = len;
    return true;
  }

  free(pat);
  return false;
}

bool parse_hex_bytes(const char* str, const uint8_t** hex_bytes, size_t* hex_bytes_length) {
  *hex_bytes = nullptr;
  *hex_bytes_length = 0;

  const auto str_len = strlen(str);
  const auto buf = (uint8_t*)malloc(str_len / 2);
  bool success = true;
  size_t len = 0;

  char lastc = ' ';
  while (auto c = *str++) {
    if (c == ' ') {
      (void)0;
    } else if (lastc != ' ') {
      const auto nibble1 = unhex(lastc);
      const auto nibble2 = unhex(c);
      if (nibble1 == 0xFF || nibble2 == 0xFF) {
        success = false;
        break;
      }
      buf[len++] = nibble1 << 4 | nibble2;
      c = ' ';
    }

    lastc = c;
  }

  if (lastc != ' ')
    success = false;

  if (success) {
    *hex_bytes = buf;
    *hex_bytes_length = len;
    return true;
  }

  free(buf);
  return false;
}

void load_config(char* config) {
  const jsonParser json(config);
  const auto root = json.root();
  if (json_getType(root) != JSON_ARRAY)
    fail("Root object isn't an array!");
  for (auto it = json_getChild(root); it; it = json_getSibling(it)) {
    auto entry = (patch_entry*)malloc(sizeof(struct patch_entry));
    *entry = {};
    if (json_getType(it) != JSON_OBJ)
      fail("Patch entry is not an object!");
    bool success = true;

#define GET_PROP(name) success = success && json_tryGetProperty(it, #name, entry->name)

    GET_PROP(min_matches);
    GET_PROP(max_matches);

    GET_PROP(on_initialize);
    GET_PROP(on_process_initialized);
    GET_PROP(on_before_dllmain);

    GET_PROP(is_code);
    GET_PROP(allowed_to_fail);
    GET_PROP(multishot);

#undef GET_PROP

    if (!success)
      fail("Malformed config (type mismatch)!");

    const auto modules = json_getProperty(it, "modules");
    if (!modules || json_getType(modules) != JSON_ARRAY)
      fail("Malformed config (type mismatch)!");
    const auto modules_length = json_getChildrenCount(modules);
    const auto modules_arr = (const char**)malloc(modules_length * sizeof(char*));
    size_t modules_counter = 0;
    for (auto jt = json_getChild(modules); jt; jt = json_getSibling(jt)) {
      if (json_getType(jt) != JSON_TEXT)
        fail("Malformed config (type mismatch)!");
      const auto str = json_getValue(jt);
      const auto buf = (char*)malloc(strlen(str) + 1);
      strcpy(buf, str);
      modules_arr[modules_counter++] = buf;
    }

    entry->modules_length = modules_length;
    entry->modules = modules_arr;

    const auto pattern = json_getProperty(it, "pattern");
    if (!pattern || json_getType(pattern) != JSON_TEXT)
      fail("Malformed config (type mismatch)!");

    if (!parse_pattern(json_getValue(pattern), &entry->pattern, &entry->pattern_length))
      fail("Malformed pattern!");

    const auto replacement = json_getProperty(it, "replacement");
    if (!replacement || json_getType(replacement) != JSON_TEXT)
      fail("Malformed config (type mismatch)!");

    if (!parse_hex_bytes(json_getValue(replacement), &entry->replacement, &entry->replacement_length))
      fail("Malformed replacement!");

    entry->next = s_patches_head;
    s_patches_head = entry;
  }
}

void initialize() {
  s_original_post_init = (PPS_POST_PROCESS_INIT_ROUTINE)NtCurrentPeb()->PostProcessInitRoutine;
  NtCurrentPeb()->PostProcessInitRoutine = (PVOID)&post_process_init;

  PVOID ntdll{};
  RtlPcToFileHeader(&RtlPcToFileHeader, &ntdll);
  const auto pLdrRegisterDllNotification = GET_EXPORT(LdrRegisterDllNotification);
  pLdrRegisterDllNotification(0, &dll_notification, nullptr, &s_dll_notification_cookie);

  const auto config = get_config();
  if (!config)
    fail("Failed to get config!");
  load_config(config);

  iterate_modules(patch_check_reason::initialize);
}

extern "C" __declspec(dllexport) void* dummy() {
  return nullptr;
}

extern "C" BOOL WINAPI dll_entry(HINSTANCE, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    initialize();
  }
  return TRUE;
}
