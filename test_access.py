import tempfile
import unittest
from pathlib import Path

from access import choose_key, order_attempts, parse_agent_line, parse_logins, render_ssh_config, splice_ssh_config


class AccessTests(unittest.TestCase):
    def test_parse_keeps_a_comment_with_spaces(self):
        parsed = parse_agent_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHdummykeymaterialxxxxxxxxxxxxxxxxxxx id_ed25519 (main github)")
        self.assertEqual(parsed["comment"], "id_ed25519 (main github)")
        self.assertIsNone(parse_agent_line("not a key"))

    def test_logins_try_the_typed_password_before_the_saved_list(self):
        saved = parse_logins("pi pi\nsabrodigan secret\n# skip\n1bad secret\n")
        self.assertEqual(saved, [("pi", "pi"), ("sabrodigan", "secret")])
        tried = order_attempts("pi", "typed", saved)
        self.assertEqual(tried[0], ("pi", "typed"))
        self.assertIn(("sabrodigan", "secret"), tried)
        self.assertEqual(len(tried), 3)

    def test_termius_key_wins_over_github_and_deploy_keys(self):
        keys = [
            {"type": "ssh-rsa", "comment": "google_compute_engine", "line": "ssh-rsa A google_compute_engine"},
            {"type": "ssh-ed25519", "comment": "id_ed25519 (main github)", "line": "ssh-ed25519 B github"},
            {"type": "ssh-rsa", "comment": "termius_gcp_key", "line": "ssh-rsa C termius_gcp_key"},
            {"type": "ssh-rsa", "comment": "id_boxtracker", "line": "ssh-rsa C id_boxtracker"},
        ]
        chosen = choose_key(keys, prefer="termius")
        self.assertEqual(chosen["comment"], "termius_gcp_key")

    def test_ssh_config_offers_only_the_one_key(self):
        block = render_ssh_config(
            [
                {"ip": "192.168.1.64", "hostname": "raspberrypi8gb", "ssh_user": "pi"},
                {"ip": "192.168.1.110", "hostname": "ras5-AI-2", "ssh_user": "pi"},
                {"ip": "", "hostname": "bad name", "ssh_user": "pi"},
            ],
            "/home/sabrodigan/.ssh/pilocate_pi.pub",
            "/home/sabrodigan/.1password/agent.sock",
        )
        self.assertIn("Host 192.168.1.64 raspberrypi8gb 192.168.1.110 ras5-AI-2", block)
        self.assertNotIn("bad name", block)
        self.assertIn("IdentitiesOnly yes", block)
        self.assertIn("IdentityFile /home/sabrodigan/.ssh/pilocate_pi.pub", block)
        existing = "Host github.com\n  User git\n"
        merged = splice_ssh_config(existing, block)
        self.assertIn("Host github.com", merged)
        again = splice_ssh_config(merged, block)
        self.assertEqual(again.count("# pilocate begin"), 1)

    def test_splice_writes_a_file_without_touching_other_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config"
            path.write_text("Host github.com\n  User git\n")
            from access import update_ssh_config
            update_ssh_config(
                [{"ip": "192.168.1.64", "hostname": "raspberrypi8gb", "ssh_user": "pi"}],
                config_path=path,
            )
            text = path.read_text()
            self.assertIn("Host github.com", text)
            self.assertIn("Host 192.168.1.64 raspberrypi8gb", text)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
