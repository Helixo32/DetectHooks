# DetectHooks

[![Nim Version](https://img.shields.io/badge/nim-2.0.0-orange.svg)](https://nim-lang.org/)

DetectHooks identifies userland hooks placed by AD/EDR, enabling you to prepare your offensive tools accordingly.

This tool enumerate functions exported from ntdll.dll, looking for modified instruction at the start of the syscall stub, indicating redirection of the execution somewhere else (module of AV/EDR) for inspection.



# Usage
- Dependencies
  ```
  nimble install winim
  ```
- Compilation
  - Linux
    ```
    nim --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc c DetectHooks.nim
    ```
  - Windows
    ```
    nim c DetectHooks.nim
    ```
- Execution
  ```
  DetectHooks.exe
  ```


# Demo
https://raw.githubusercontent.com/Helixo32/DetectHooks/main/DetectHooks.mp4?token=GHSAT0AAAAAACHEMJ2DBMEMTKDEL4YJ3TDEZHV6IZQ
