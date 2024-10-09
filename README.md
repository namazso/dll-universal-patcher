# DLL Universal Patcher

A universal binary patching dll. Meant to be used with [DLL Proxy Generator](https://github.com/namazso/dll-proxy-generator).

## How to use

1. Pick a suitable dll to proxy, like `version.dll`
2. Use `dll-proxy-generator.exe --import-dll "dll_universal_patcher.dll" --import "dummy" "C:\Windows\System32\version.dll"` to generate a suitable proxy dll.
3. Write up your patches into `patches.json` (more on this later)
4. Place the generated dll, `dll_universal_patcher.dll`, and `patches.json` in target directory to perform dll hijacking

## patches.json

Example:

```json
[
    {
        "modules": [ "winver.exe", "{exe}" ],
        "pattern": "01 02 03 04 05 ? 06 ?? 07",
        "replacement": "90 90 90 90 C3",
        "min_matches": 1,
        "max_matches": 3,
        "on_initialize": false,
        "on_process_initialized": true,
        "on_before_dllmain": false,
        "is_code": true,
        "allowed_to_fail": false,
        "multishot": false
    }
]
```

For more info, check out [the schema](patches.schema.json)