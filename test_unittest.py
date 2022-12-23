#! /usr/local/bin/python3.10


import unittest
from network_attacker import scan_port, available, brute_force
import network_attacker


class TestClassScanPort(unittest.TestCase):
    def test_scan_port(self):
        network_attacker.target = '192.168.0.102'
        self.assertTrue(scan_port(22))
        self.assertFalse(scan_port(80))

    def test_scan_false_port(self):
        network_attacker.target = '192.168.0.110'
        self.assertFalse(scan_port(22))
        self.assertFalse(scan_port(80))


class TestClassAvailable(unittest.TestCase):
    def test_false_available(self):
        network_attacker.target = '192.168.0.110'
        self.assertFalse(available())

    def test_available(self):
        network_attacker.target = '192.168.0.102'
        self.assertTrue(available())


class TestClassBruteForce(unittest.TestCase):
    def test_brute_force(self):
        network_attacker.target = '192.168.0.102'
        self.assertEqual(brute_force(22, 'test'), 'connected')

    def test_brute_force_wrong_user(self):
        network_attacker.target = '192.168.0.102'
        self.assertNotEqual(brute_force(22, 'tess'), 'connected')

    def test_brute_force_wrong_port(self):
        network_attacker.target = '192.168.0.102'
        self.assertNotEqual(brute_force(80, 'test'), 'connected')

    def test_brute_force_false(self):
        network_attacker.target = '192.168.0.10'
        self.assertNotEqual(brute_force(22, 'test'), 'connected')


if __name__ == '__main__':
    unittest.main()
