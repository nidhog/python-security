from unittest import TestCase
from otp import OTP

__author__ = 'Terry Chia'


class TestOTP(TestCase):
    def setUp(self):
        self.otp = OTP()
        self.secret = '12345678901234567890'

    def test_generate_hotp(self):
        # Test vectors taken from RFC 4226, Appendix E

        self.assertEqual('755224', self.otp.generate_hotp(self.secret, 0))
        self.assertEqual('287082', self.otp.generate_hotp(self.secret, 1))
        self.assertEqual('359152', self.otp.generate_hotp(self.secret, 2))
        self.assertEqual('969429', self.otp.generate_hotp(self.secret, 3))
        self.assertEqual('338314', self.otp.generate_hotp(self.secret, 4))
        self.assertEqual('254676', self.otp.generate_hotp(self.secret, 5))
        self.assertEqual('287922', self.otp.generate_hotp(self.secret, 6))
        self.assertEqual('162583', self.otp.generate_hotp(self.secret, 7))
        self.assertEqual('399871', self.otp.generate_hotp(self.secret, 8))
        self.assertEqual('520489', self.otp.generate_hotp(self.secret, 9))

    def test_generate_totp(self):
        # Test vectors taken from RFC 6238, Appendix B

        self.assertEqual('94287082', self.otp.generate_totp(self.secret, 59, 8))
        self.assertEqual('07081804', self.otp.generate_totp(self.secret, 1111111109, 8))
        self.assertEqual('14050471', self.otp.generate_totp(self.secret, 1111111111, 8))
        self.assertEqual('89005924', self.otp.generate_totp(self.secret, 1234567890, 8))
        self.assertEqual('69279037', self.otp.generate_totp(self.secret, 2000000000, 8))
        self.assertEqual('65353130', self.otp.generate_totp(self.secret, 20000000000, 8))

    def test_validate_hotp(self):
        self.assertTrue(self.otp.validate_hotp('755224', self.secret, 0))
        self.assertTrue(self.otp.validate_hotp('287082', self.secret, 0))
        self.assertFalse(self.otp.validate_hotp('969429', self.secret, 0))

    def test_validate_totp(self):
        self.assertTrue(self.otp.validate_totp('07081804', self.secret, 1111111109, 8))
        self.assertTrue(self.otp.validate_totp('07081804', self.secret, 1111111084, 8))
        self.assertFalse(self.otp.validate_totp('07081804', self.secret, 1111111078, 8))
        self.assertTrue(self.otp.validate_totp('07081804', self.secret, 1111111134, 8))
        self.assertFalse(self.otp.validate_totp('07081804', self.secret, 1111111140, 8))