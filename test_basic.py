from network_attacker import scan_port, available, brute_force
import network_attacker


class TestClassScanPort:
    def test_scan_port(self):
        assert scan_port(22) == True
        assert scan_port(80) == False

    def test_scan_false_port(self):
        network_attacker.target = '192.168.0.110'
        assert scan_port(22) == False
        assert scan_port(80) == False


class TestClassAvailable:
    def test_false_available(self):
        network_attacker.target = '192.168.0.110'
        assert available() == False

    def test_available(self):
        network_attacker.target = '192.168.0.102'
        assert available() == True


class TestClassBruteForce:
    def test_brute_force(self):
        network_attacker.target = '192.168.0.102'
        assert brute_force(22, 'test') == 'connected'

    def test_brute_force_wrong_user(self):
        network_attacker.target = '192.168.0.102'
        assert brute_force(22, 'tess') != 'connected'

    def test_brute_force_wrong_port(self):
        network_attacker.target = '192.168.0.102'
        assert brute_force(80, 'test') != 'connected'

    def test_brute_force_false(self):
        network_attacker.target = '192.168.0.10'
        assert brute_force(22, 'test') != 'connected'
