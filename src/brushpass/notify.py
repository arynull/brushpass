"""Webhook notifications for credential rotations.

Best-effort by construction. A rotation that succeeds but whose webhook
fails is still a successful rotation: the notifier swallows every
exception, records what happened on the outcome, and returns. The
opposite would be worse — a chat server outage would report a credential
change as failed, and an operator who believed that would go looking for
a rotation that actually happened fine.

Configure with ``notifications.webhook_url`` in the config file::

    notifications:
      webhook_url: https://hooks.example.com/services/T000/B000/XXXX

The payload is the rotation outcome as JSON: no secret material, only
identifiers and durations. It is the same structure ``rotate --json``
prints, so a receiver can parse one thing.
"""

from .rotate import RotationOutcome, send_webhook


class WebhookNotifier:
    """Posts a rotation summary to a webhook URL."""

    def __init__(self, url: str, sender=None):
        self.url = url
        self._send = sender or send_webhook

    @classmethod
    def from_config(cls, config, sender=None) -> "WebhookNotifier | None":
        """Build a notifier from config, or None when no URL is set."""
        url = (getattr(config, "webhook_url", None) or "").strip()
        return cls(url, sender=sender) if url else None

    def __call__(self, outcome: RotationOutcome) -> None:
        """Deliver the summary. Never raises."""
        try:
            self._send(self.url, self.payload(outcome))
        except Exception as exc:  # noqa: BLE001 - best effort by contract
            raise NotificationError(str(exc)) from None

    @staticmethod
    def payload(outcome: RotationOutcome) -> dict:
        """The JSON body. Identifiers and timings only, never secrets."""
        body = outcome.to_dict()
        body["event"] = "credential.rotation"
        return body


class NotificationError(Exception):
    """A webhook could not be delivered.

    Carries the message only. The engine records it as a warning and
    carries on: the credential change has already been committed.
    """
