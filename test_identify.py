import unittest

from identify import is_pi_mac, is_pi_name, is_raspberry_pi, normal_mac


class IdentifyTests(unittest.TestCase):
    def test_known_prefixes(self):
        self.assertTrue(is_pi_mac("e4:5f:01:05:1f:aa"))
        self.assertTrue(is_pi_mac("DC-A6-32-55-2D-D1"))
        self.assertTrue(is_pi_mac("d8:3a:dd:c3:ed:08"))
        self.assertFalse(is_pi_mac("aa:bb:cc:dd:ee:ff"))
        self.assertEqual(normal_mac("e4-5f-01-05-1f-aa"), "E4:5F:01:05:1F:AA")

    def test_house_names(self):
        self.assertTrue(is_pi_name("raspberrypi8gb.vodafone.ultrahub"))
        self.assertTrue(is_pi_name("ras5-AI-2.vodafone.ultrahub"))
        self.assertTrue(is_pi_name("storm-ras4b.vodafone.ultrahub"))
        self.assertTrue(is_pi_name("ras-5b.vodafone.ultrahub"))
        self.assertFalse(is_pi_name("leias-iPad.local"))
        self.assertFalse(is_pi_name("NAS1a.vodafone.ultrahub"))

    def test_either_signal_is_enough(self):
        self.assertTrue(is_raspberry_pi({"hostname": "camera"}, "b8:27:eb:00:00:01"))
        self.assertTrue(is_raspberry_pi({"hostname": "ras-5b"}, ""))
        self.assertFalse(is_raspberry_pi({"hostname": "iPhone"}, "3c:22:fb:00:00:01"))


if __name__ == "__main__":
    unittest.main()
