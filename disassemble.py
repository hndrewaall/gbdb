from distorm3 import Decode, Decode64Bits
from tempfile import SpooledTemporaryFile


def decode_bytes(bytes):
    temp = SpooledTemporaryFile()
    string = ""
    for byte in bytes:
        string = string + chr(byte)
    temp.write(string)
    temp.seek(0)  # work around a stupid python bug
    return Decode(0, temp.read(), Decode64Bits)
