import unittest
from datetime import datetime, timedelta, timezone

from updates import check_is_stale, due_at, next_check, parse_updates, readable_failure


class UpdateTests(unittest.TestCase):
    def test_summary_counts_upgrades_and_new_packages(self):
        text = "\n".join([
            "update_ok yes",
            "Inst python3 [3.11.2-1] (3.11.2-6 Raspberry Pi OS:stable)",
            "2 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.",
        ])
        report = parse_updates(text)
        self.assertEqual(report["upgraded"], 2)
        self.assertEqual(report["new"], 1)
        self.assertEqual(report["count"], 3)
        self.assertTrue(report["lists_refreshed"])

    def test_a_clean_pi_reports_zero(self):
        report = parse_updates("update_ok yes\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
        self.assertEqual(report["count"], 0)

    def test_missing_summary_is_refused(self):
        with self.assertRaises(RuntimeError):
            parse_updates("update_ok no\nReading package lists...\n")

    def test_an_unreachable_pi_gets_a_plain_reason(self):
        self.assertEqual(
            readable_failure("ssh: connect to host 192.168.1.202 port 22: No route to host", "192.168.1.202"),
            "192.168.1.202 did not answer, so the package count was not read.",
        )

    def test_daily_check_is_due_after_0400_until_it_has_run(self):
        zone = timezone(timedelta(hours=0))
        afternoon = datetime(2026, 11, 9, 15, 15, tzinfo=zone)
        self.assertEqual(due_at(afternoon).hour, 4)
        self.assertTrue(check_is_stale(None, afternoon))
        self.assertTrue(check_is_stale("2026-11-09T03:30:00+00:00", afternoon))
        self.assertFalse(check_is_stale("2026-11-09T04:05:00+00:00", afternoon))
        self.assertEqual(next_check(afternoon), datetime(2026, 11, 10, 4, 0, tzinfo=zone))
        early = datetime(2026, 11, 10, 3, 0, tzinfo=zone)
        self.assertFalse(check_is_stale("2026-11-09T15:20:00+00:00", early))
        self.assertEqual(next_check(early), datetime(2026, 11, 10, 4, 0, tzinfo=zone))


if __name__ == "__main__":
    unittest.main()
