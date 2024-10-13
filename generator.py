import random
import binascii
import ecdsa
import hashlib
import sys
import json
import requests
from requests.auth import HTTPBasicAuth

from base58 import b58encode
def secret_to_address(secret, pfv,legacy=False):
    pubk_pair = from_secret_pubk_point(secret)
    compressed_pubk, pubk = _pubk_to_compressed_pubk(*pubk_pair)
    address = _pubk_to_address(pubk,pfv) if legacy else _pubk_to_address(compressed_pubk,pfv)

    return address


def from_secret_pubk_point(secret):
    CURVE = ecdsa.SECP256k1

    sk = ecdsa.SigningKey.from_secret_exponent(secret, curve=CURVE)
    pubk_vk = sk.verifying_key  # the point
    pubk = binascii.b2a_hex(pubk_vk.to_string()).decode('ascii')

    pubk_x = pubk[:64]
    pubk_y = pubk[64:]

    return pubk_x, pubk_y


def _pubk_to_compressed_pubk(pubk_x, pubk_y):
    EVEN_PREFIX = '02'
    UNEVEN_PREFIX = '03'
    LEGACY_PREFIX = '04'
    y_parity = ord(bytearray.fromhex(pubk_y[-2:])) % 2
    prefix = EVEN_PREFIX if y_parity==0 else UNEVEN_PREFIX
    compressed_pubk = prefix + pubk_x

    pubk = LEGACY_PREFIX + pubk_x + pubk_y

    return compressed_pubk, pubk


def _pubk_to_address(pubk,prf):
    pubk_array = bytearray.fromhex(pubk)

    sha = hashlib.sha256()  
    sha.update(pubk_array)
    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())
    if prf=="0":
        PREFIX = "00"
    elif prf=="1":
        PREFIX="30"
    elif prf=="2":
        PREFIX = "1e"
    key_hash = PREFIX + rip.hexdigest()
    sha = hashlib.sha256()
    sha.update(bytearray.fromhex(key_hash))
    checksum = sha.digest()
    sha = hashlib.sha256()
    sha.update(checksum)
    checksum = sha.hexdigest()[0:8]
    address_hex = key_hash + checksum
    
    bs = bytes(bytearray.fromhex(address_hex))
    address = b58encode(bs).decode('utf-8')

    return address


def secret_to_wif(secret,prf):
    if prf=="0":
        PREFIX="80"
    elif prf=="1":
        PREFIX="B0"
    elif prf=="2":
        PREFIX="9e"
    
    hex_string = hex(secret)[2:].zfill(64)
    pre_hash = PREFIX + hex_string

    hash_1 = hashlib.sha256(binascii.unhexlify(pre_hash)).hexdigest()
    hash_2 = hashlib.sha256(binascii.unhexlify(hash_1)).hexdigest()
    checksum = hash_2[:8]

    pre_hash_checksum = pre_hash + checksum
    from_hex_string = int(pre_hash_checksum, 16)
    def _get(idx):
        ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        m = 58**idx
        idx = from_hex_string // m % 58
        return ALPHABET[idx]
    IDXS = range(51)
    wif_str = "".join(map(_get, IDXS))

    # Reverse
    rev_wif_str = wif_str[::-1].lstrip('1')

    return rev_wif_str
if __name__ == "__main__":
    txF=""
    arrtxt=[]
    def tryx():
        s=input("Choose one of the options\nBitcoin: 0\nLitecoin: 1\nDogecoin: 2\n")
        if s!="0" and s!="1" and s!="2":
            print("Invalid option, type a number between 1 and 3")
            return ""
        return s
    def chkZ():
        z=input("----\nAmount of private keys\n")
        try:
            if int(z)>10:
                print("Maximum 25 private keys at a time")
                return ""
            return z
        except:
            print("input must be integer")
            return ""
    def qxA():
        d=input("type y or n if you want save public addresses in a json file\n")
        if d.lower()=="y":
            return "y"        
    sv=False
    r=""
    while True:
        s=tryx()
        if s!="":
            z=chkZ()
            if z!="":
                w=qxA()
                if w!="y":
                    break
                r=input("Type name to json eg: dogeAdrs\n")
                sv=True
                break
    for _ in range(int(z)):
        random_number = random.randrange(2**204,2**256-25)
        address_legacy = secret_to_address(random_number,s,True)
        address = secret_to_address(random_number,s)
        wif = secret_to_wif(random_number,s)
        l=0
        js={"wif":wif,"address_legacy":address_legacy,"random_numb":random_number}
        js0={"Address uncompressed":address_legacy,"Address compressed":address}
        arrtxt.append(js0)
        txF+=f'Wif: {wif}\nAdr Unc: {address_legacy}\nAdr: {address}\nRandom: {random_number}\n\n'
    if sv:
        with open(f"{r}.json","w") as e:
            json.dump(arrtxt,e)
    import subprocess
    command = f'echo "{txF}" > /dev/usb/lp0'
    subprocess.run(command, shell=True)

