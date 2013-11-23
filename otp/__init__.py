import hashlib
import hmac
import random
import struct
import math
import time

__author__ = 'Terry Chia'


class OTP:

    def generate_secret(self, size_in_bits=160):
        """Securely generates random secret using the system's CSPRNG.

        Keyword arguments:
        size_in_bits -- Size of random secret to generate (default 160 bits)

        Returns:
        Random secret of specified size securely generated using the system's
        CSPRNG. This is /dev/urandom for *nix-based systems and CryptGenRandom
        for Windows-based systems.

        """
        rand = random.SystemRandom()
        return rand.getrandbits(size_in_bits)

    def generate_hotp(self, secret, counter, length=6):
        """Generates an HOTP value.

        Keyword arguments:
        secret -- The shared secret used to generate the HOTP value. This secret
        should be 160 bits as per RFC 4226.
        counter -- The counter value used to generate the HOTP value. The counter
        must be 8 bytes long and synchronized between the client and server.
        length -- The length of the HOTP value to generate. (default 6)

        Returns:
        The generated HOTP value of the specified length.
        .
        """
        HS = hmac.new(secret, struct.pack('>Q', counter), hashlib.sha1).digest()
        sbit = self._dynamic_truncate(HS)
        return str(sbit % (10**length)).zfill(length)

    def generate_totp(self, secret, time, length=6):
        """Generates an TOTP value.

        Keyword arguments:
        secret -- The shared secret used to generate the TOTP value. This secret
        should be 160 bits as per RFC 4226.
        time -- The time value used to generate the TOTP value. The time value is
        the current unix time expressed as an integer.
        length -- The length of the HOTP value to generate. (default 6)

        Returns:
        The generated TOTP value of the specified length.

        """
        totp = self.generate_hotp(secret, int(math.floor(time/30)), length)
        return totp.zfill(length)

    def _dynamic_truncate(self, hmac_value):
        """Extracts a 4 byte binary value from a 20 byte HMAC-SHA1 result

        This function is described in RFC 4226 Section 5.3

        Keyword arguments:
        hmac_value -- The HMAC-SHA1 result to truncate

        Returns:
        The truncated 4 byte binary value.

        """
        offset_bits = ord(hmac_value[19]) & 0b1111
        offset = int(offset_bits)
        P = hmac_value[offset:offset+4]
        return struct.unpack('>I', P)[0] & 0x7fffffff

    def _get_current_unix_time(self):
        """Returns the current unix time as an integer."""
        return int(time.time())