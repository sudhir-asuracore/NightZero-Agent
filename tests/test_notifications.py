import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from nightzero.models import IncidentContext, IncidentRecord, IncidentStatus, RootCauseAnalysis
from nightzero.notifications import DEFAULT_NOTIFICATION_SETTINGS, NotificationDispatcher
from nightzero.store import ArtifactStore
from nightzero.workflow import NightZeroWorkflow


class NotificationDispatcherTest(unittest.TestCase):
    def test_default_notification_settings(self) -> None:
        self.assertFalse(DEFAULT_NOTIFICATION_SETTINGS["email"]["enabled"])
        self.assertFalse(DEFAULT_NOTIFICATION_SETTINGS["telegram"]["enabled"])
        self.assertFalse(DEFAULT_NOTIFICATION_SETTINGS["slack"]["enabled"])
        self.assertTrue(DEFAULT_NOTIFICATION_SETTINGS["triggers"]["on_incident_detected"])

    def test_test_channel_email_validation(self) -> None:
        success, msg = NotificationDispatcher.test_channel("email", {"smtp_host": ""})
        self.assertFalse(success)
        self.assertIn("required", msg)

    def test_test_channel_telegram_validation(self) -> None:
        success, msg = NotificationDispatcher.test_channel("telegram", {"bot_token": ""})
        self.assertFalse(success)
        self.assertIn("required", msg)

    def test_test_channel_slack_validation(self) -> None:
        success, msg = NotificationDispatcher.test_channel("slack", {"webhook_url": ""})
        self.assertFalse(success)
        self.assertIn("required", msg)

    @patch("urllib.request.urlopen")
    def test_send_telegram_success(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"ok": true}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        success, msg = NotificationDispatcher.send_telegram_message(
            {"bot_token": "12345:TOKEN", "chat_id": "123456"}, "Test Alert"
        )
        self.assertTrue(success)
        self.assertIn("delivered", msg)

    @patch("urllib.request.urlopen")
    def test_send_slack_success(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        success, msg = NotificationDispatcher.send_slack_webhook(
            {"webhook_url": "https://hooks.slack.com/services/T/B/X", "channel": "#alerts"},
            {"text": "Test alert"},
        )
        self.assertTrue(success)
        self.assertIn("delivered", msg)

    def test_workflow_notification_settings_persistence(self) -> None:
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            workflow = NightZeroWorkflow(root, store, str(root.parent / "NightZero-TestProject"))
            settings = workflow.notification_settings
            self.assertIn("email", settings)
            self.assertIn("telegram", settings)
            self.assertIn("slack", settings)

            updated = {**settings, "telegram": {"enabled": True, "bot_token": "TOK", "chat_id": "123"}}
            workflow.set_notification_settings(updated)
            self.assertTrue(workflow.notification_settings["telegram"]["enabled"])
            self.assertEqual("TOK", workflow.notification_settings["telegram"]["bot_token"])


if __name__ == "__main__":
    unittest.main()
