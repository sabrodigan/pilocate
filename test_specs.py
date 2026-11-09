import unittest

from specs import format_clock, format_cpu, format_ram, parse_hardware


class SpecTests(unittest.TestCase):
    def test_known_boards_round_to_the_installed_memory_and_clock(self):
        text = "\n".join([
            "uname Linux ras5-AI-2 6.18.50 aarch64 GNU/Linux",
            "board Raspberry Pi 5 Model B Rev 1.1",
            "cpu Cortex-A76",
            "cores 4",
            "ram_kb 16603424",
            "clock_khz 2400000",
        ])
        specs = parse_hardware(text)
        self.assertEqual(specs["board"], "Raspberry Pi 5 Model B Rev 1.1")
        self.assertEqual(specs["cpu"], "Cortex-A76, 4 cores")
        self.assertEqual(specs["ram"], "16 GB")
        self.assertEqual(specs["clock"], "2.4 GHz")
        self.assertIn("Linux ras5-AI-2", specs["uname"])

    def test_smaller_boards(self):
        self.assertEqual(format_ram("7999812"), "8 GB")
        self.assertEqual(format_ram("3930868"), "4 GB")
        self.assertEqual(format_clock("1800000"), "1.8 GHz")
        self.assertEqual(format_clock("1500000"), "1.5 GHz")
        self.assertEqual(format_cpu("Cortex-A72", "4"), "Cortex-A72, 4 cores")
        self.assertEqual(format_cpu("-", "4"), "4 cores")

    def test_a_reply_without_a_board_or_kernel_is_refused(self):
        with self.assertRaises(RuntimeError):
            parse_hardware("cpu Cortex-A76\ncores 4\n")


if __name__ == "__main__":
    unittest.main()
