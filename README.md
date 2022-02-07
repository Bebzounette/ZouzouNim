Zouzounim
==========

Playing around with [Offensive Nim](https://github.com/byt3bl33d3r/OffensiveNim#reflectively-loading-nim-executables)

Features:

* Direct syscalls for triggering Windows Native API functions with [NimlineWhispers2](https://github.com/ajpc500/NimlineWhispers2).
* Shellcode encryption/decryption with [AES in CTR mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)).
* Patching the AMSI with [Offensive Nim module](https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_patch_bin.nim)
* Simple sandbox detection.

> **DISCLAIMER.** All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any illegal use of this tool.

## Usage

Installation:

```console
~$ git clone --recurse-submodules https://github.com/Zeckers/ZouzouNim.git && cd ZouzouNim
~$ git submodule update --init --recursive
~$ nimble install winim nimcrypto
~$ pip3 install -r requirements.txt
```

Example:

```console
~$ msfvenom -a x64 --platform windows -p windows/exec cmd=calc.exe -f c -o shellcode.bin
~$ python.exe .\ZouzouNim.py calc-thread64.bin -o Basic_injector -r -p notepad.exe --debug
~$ Open notepad.exe 
~$ .\Basic_injector.exe
```

Help:

```
usage: ZouzouNim.py [-h] [-p PROCESS] [-o OUTPUT] [-r] [--debug] shellcode_bin

positional arguments:
  shellcode_bin         path to the raw shellcode file

optional arguments:
  -h, --help            show this help message and exit
  -p PROCESS, --process PROCESS
                        process to inject (default "C:\Windows\explorer.exe")
  -o OUTPUT, --output OUTPUT
                        output filename
  -r, --rdmsyscalls     use NimlineWhispers2 to randomize direct syscalls and generate syscalls.nim
  --debug               do not strip debug messages from Nim binary
```