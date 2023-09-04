import winim
import strformat
import pointers


proc DetectHook(): void=
    var
        pBase                           : ByteAddress
        pImgDosHdr                      : PIMAGE_DOS_HEADER
        pImgNtHdrs                      : PIMAGE_NT_HEADERS
        imgFileHdr                      : IMAGE_FILE_HEADER
        imgOptHdr                       : IMAGE_OPTIONAL_HEADER
        pDataDirectory                  : PIMAGE_DATA_DIRECTORY
        pImgExportDir                   : PIMAGE_EXPORT_DIRECTORY
        functionNameArray               : PDWORD
        sFunctionName                   : string
        pFunctionName                   : cstring
        library                         : HINSTANCE
        bytesRead                       : SIZE_T
        libraryAddress                  : FARPROC
        hModule                         : HMODULE               = GetModuleHandleA("ntdll.dll")
        bytesInstruction                : array[4, byte]
        bytesInstructionHex             : array[4, string]
        originalBytesInstructionHex     : array[4, string]      = ["4C", "8B", "D1", "B8"]          # mov r10, rcx; mov eax
        falsePositive                   : array[7, string]
        isFalsePositive                 : bool
        count                           : int                   = 1
        count1                          : int                   = 0

    pBase                   = cast[ByteAddress](hModule)
    pImgDosHdr              = cast[PIMAGE_DOS_HEADER](pBase)
    pImgNtHdrs              = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](pBase) + pImgDosHdr.e_lfanew)
    imgFileHdr              = pImgNtHdrs.FileHeader
    imgOptHdr               = pImgNtHdrs.OptionalHeader
    pDataDirectory          = cast[PIMAGE_DATA_DIRECTORY](addr imgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT])
    pImgExportDir           = cast[PIMAGE_EXPORT_DIRECTORY](pBase + pDataDirectory.VirtualAddress)

    # Getting the function's names array pointer
    functionNameArray       = cast[PDWORD](pBase + pImgExportDir.AddressOfNames)

    # false positive array
    falsePositive = ["NtGetTickCount", "NtQuerySystemTime", "NtdllDefWindowProc_A", "NtdllDefWindowProc_W", "NtdllDialogWndProc_A", "NtdllDialogWndProc_W" ,"ZwQuerySystemTime"]

    library = LoadLibraryA("ntdll.dll")
    if library == 0:
        echo fmt"[-] LoadLibraryA failed        : {GetLastError()}"
        return

    # Looping through all the exported functions
    while count < pImgExportDir.NumberOfFunctions:
        count1 = 0
        isFalsePositive = false

        ptrMath:
            pFunctionName = cast[cstring](pBase + cast[SIZE_T](functionNameArray[count]))

            sFunctionName = $pFunctionName
            if sFunctionName[0 .. 1] == "Nt" or sFunctionName[0 .. 1] == "Zw":
                libraryAddress = GetProcAddress(library, pfunctionName)
                if libraryAddress == NULL:
                    echo fmt"[-] GetProcAddress failed      : {GetLastError()}" 
                    return

                ReadProcessMemory(GetCurrentProcess(), libraryAddress, &bytesInstruction, 4, &bytesRead)

                # byte to hex format
                for i in bytesInstruction:
                    bytesInstructionHex[count1] = i.toHex
                    count1+=1

                if $bytesInstruction[0] == "0":
                    echo "[-] ReadProcessMemory failed      : {GetLastError()"
                    return

                # check if 4 first byte == original
                if bytesInstructionHex == originalBytesInstructionHex:
                    count+=1
                    continue
                else:
                    for f in falsePositive:
                        if sFunctionName == f:
                            isFalsePositive = true
                    if isFalsePositive:
                        count+=1
                        continue

                    echo fmt"[+] Hooked                        : {pFunctionName}"
                    echo fmt"   \_[*] Original instruction     : {$originalBytesInstructionHex}"
                    echo fmt"   \_[*] Instruction              : {$bytesInstructionHex}"
                    echo ""

        count+=1



when isMainModule:
    echo """
    
##############################################################
#  _____       _            _   _    _             _         #
# |  __ \     | |          | | | |  | |           | |        #
# | |  | | ___| |_ ___  ___| |_| |__| | ___   ___ | | _____  #
# | |  | |/ _ \ __/ _ \/ __| __|  __  |/ _ \ / _ \| |/ / __| #
# | |__| |  __/ ||  __/ (__| |_| |  | | (_) | (_) |   <\__ \ #
# |_____/ \___|\__\___|\___|\__|_|  |_|\___/ \___/|_|\_\___/ #
#                                                            #
##############################################################                                                           

Author  :   Matthias Ossard
Links   :   https://www.linkedin.com/in/matthias-ossard/
            https://github.com/Helixo32
"""

    DetectHook()