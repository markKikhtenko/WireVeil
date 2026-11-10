import unittest
from pathlib import Path


class UpdateWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.workflow = (root / ".github" / "workflows" / "update.yml").read_text(
            encoding="utf-8"
        )

    def test_runner_is_pinned_during_ubuntu_latest_migration(self):
        self.assertIn("runs-on: ubuntu-24.04", self.workflow)
        self.assertNotIn("runs-on: ubuntu-latest", self.workflow)

    def test_dependency_changes_trigger_a_fresh_update(self):
        self.assertIn('- "requirements.txt"', self.workflow)

    def test_subscriptions_regenerate_every_six_hours(self):
        self.assertIn('cron: "23 */6 * * *"', self.workflow)
        self.assertNotIn('cron: "23 * * * *"', self.workflow)

    def test_external_subscription_steps_retry_transient_failures(self):
        self.assertIn(
            "python scripts/build.py --timeout 30 --retries 5", self.workflow
        )
        self.assertIn(
            "Subscription build failed after ${attempt} attempts.", self.workflow
        )
        self.assertIn(
            "Subscription health-check failed after ${attempt} attempts.", self.workflow
        )
        self.assertGreaterEqual(self.workflow.count("for attempt in 1 2 3; do"), 3)

    def test_dependency_and_runtime_downloads_have_bounded_retries(self):
        self.assertIn("--retries 10", self.workflow)
        self.assertIn("--timeout 60", self.workflow)
        self.assertEqual(self.workflow.count("--connect-timeout 20 --max-time 180"), 2)

    def test_runtime_download_retries_transient_network_failures(self):
        self.assertIn("--retry 8 --retry-delay 10 --retry-all-errors", self.workflow)
        self.assertIn("api.github.com/repos/SagerNet/sing-box/releases/tags", self.workflow)
        self.assertIn('"Accept: application/octet-stream"', self.workflow)

    def test_publish_retries_synchronize_with_main(self):
        self.assertIn(
            "git fetch origin +refs/heads/main:refs/remotes/origin/main",
            self.workflow,
        )
        self.assertIn('git rebase origin/main', self.workflow)
        self.assertIn('git rebase --abort', self.workflow)
        self.assertIn('git diff --name-only "$run_base"..origin/main --', self.workflow)
        self.assertIn("skipping stale generated output", self.workflow)

    def test_publish_skips_a_rewritten_main_history(self):
        self.assertIn(
            'git merge-base --is-ancestor "$run_base" origin/main', self.workflow
        )
        self.assertIn("main history was rewritten", self.workflow)


if __name__ == "__main__":
    unittest.main()
