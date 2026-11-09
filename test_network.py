import unittest

from locate import duration_seconds, summarize_diff, summarize_scan


class NetworkTests(unittest.TestCase):
    def test_scan_summary_counts_open_ports_and_names(self):
        summary = summarize_scan({
            "cidr": "192.168.1.0/24",
            "startedAt": "2026-11-07T20:20:00Z",
            "finishedAt": "2026-11-07T20:21:13Z",
            "hostCount": 2,
            "ports": [22, 80],
            "hosts": [
                {"ip": "192.168.1.64", "hostname": "raspberrypi8gb.lan", "openPorts": [22]},
                {"ip": "192.168.1.1", "hostname": "", "openPorts": []},
            ],
        })
        self.assertEqual(summary["hostsUp"], 2)
        self.assertEqual(summary["withOpenPorts"], 1)
        self.assertEqual(summary["named"], 1)
        self.assertEqual(summary["durationSeconds"], 73)
        self.assertEqual(summary["ports"], [22, 80])

    def test_diff_keeps_a_short_name_list(self):
        changes = summarize_diff({
            "added": [{"ip": "192.168.1.50", "hostname": "camera.lan"}],
            "removed": [{"ip": "192.168.1.9"}],
            "changed": [{"ip": "192.168.1.64", "hostname": "raspberrypi8gb.lan"}],
        })
        self.assertEqual(changes["addedNames"], ["camera"])
        self.assertEqual(changes["removedNames"], ["192.168.1.9"])
        self.assertEqual(changes["changed"], 1)

    def test_duration_rejects_a_blank_time(self):
        self.assertIsNone(duration_seconds("", "2026-11-07T20:21:13Z"))


if __name__ == "__main__":
    unittest.main()
