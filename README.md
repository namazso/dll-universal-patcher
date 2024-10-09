# DLL Universal Patcher

A universal binary patching dll. Meant to be used with [DLL Proxy Generator](https://github.com/namazso/dll-proxy-generator).

## What is this for?

DLL Universal Patcher is a flexible and convenient code patcher that doesn't touch the files on disk. It can be used for replacing any tasks that you'd otherwise achieve with on-disk patching, such as fixing old software on modern machines, or fixing bugs in others' software. In addition, due to more control over when the patching happens, it is possible to patch packed executables.

## How to use

1. Pick a suitable dll to proxy, like `version.dll`
2. Use `dll-proxy-generator.exe --import-dll "dll_universal_patcher.dll" --import "dummy" "C:\Windows\System32\version.dll"` to generate a suitable proxy dll
3. Write up your patches into `patches.json` (more on this later)
4. Place the generated dll, `dll_universal_patcher.dll`, and `patches.json` in target directory to perform dll hijacking

## How to use (Advanced)

1. Pick a suitable dll to proxy, like `version.dll`
2. Use `dll-proxy-generator.exe --import-dll "dll_universal_patcher.dll" --import "dummy" "C:\Windows\System32\version.dll"` to generate a suitable proxy dll
3. Write up your patches into `patches.json` (more on this later)
4. Use a tool like CFF Explorer to add the config as a `RCDATA` resource with ID `1` and neutral language to `dll_universal_patcher.dll`
5. Place the generated dll and `dll_universal_patcher.dll` in target directory to perform dll hijacking

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

For more info on the options, check out [the schema](patches.schema.json)