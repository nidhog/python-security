import hashlib
import hmac
import random
import struct
import math
import time

__author__ = 'Terry Chia'


class OTP:

    def generate_secret(self, size_in_bits):
        rand = random.SystemRandom()
        return rand.getrandbits(size_in_bits)

    def generate_hotp(self, secret, counter, length=6):
        HS = hmac.new(secret, struct.pack('>Q', counter), hashlib.sha1).digest()
        sbit = self._dynamic_truncate(HS)
        return str(sbit % (10**length)).zfill(length)

    def generate_totp(self, secret, time, length):
        totp = self.generate_hotp(secret, int(math.floor(time/30)), length)
        return totp.zfill(length)

    def _dynamic_truncate(self, hmac_value):
        offset_bits = ord(hmac_value[19]) & 0b1111
        offset = int(offset_bits)
        P = hmac_value[offset:offset+4]
        return struct.unpack('>I', P)[0] & 0x7fffffff

    def _get_current_unix_time(self):
        return int(time.time())