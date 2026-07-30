"""Alert manager — deduplication, rate limiting, webhook dispatch."""

import json
from datetime import datetime, timezone


class AlertManager:
    def __init__(self, config, logger=None):
        self._cfg = config.get("guard", {})
        self._logger = logger
        self._alert_history = []
        self._discord_webhook = self._cfg.get("alert_webhook_discord", "")

    def process(self, alerts: list) -> list:
        """Deduplicate and filter alerts, then dispatch."""
        filtered = self._deduplicate(alerts)
        self._alert_history.extend(filtered)

        # Keep only last 1000 alerts
        if len(self._alert_history) > 1000:
            self._alert_history = self._alert_history[-500:]

        # Dispatch to Discord
        if self._discord_webhook:
            for alert in filtered:
                self._send_discord(alert)

        return filtered

    def _deduplicate(self, alerts: list) -> list:
        """Remove duplicate alerts within the same batch and within 10 minutes."""
        result = []
        seen = set()
        for alert in alerts:
            # Check against history
            is_dup = False
            for existing in reversed(self._alert_history[-20:]):
                if existing.title == alert.title:
                    delta = (alert.timestamp - existing.timestamp).total_seconds()
                    if delta < 600:
                        is_dup = True
                        break
            # Check against already-deduped in this batch
            if not is_dup and alert.title in seen:
                is_dup = True
            if not is_dup:
                seen.add(alert.title)
                result.append(alert)
        return result

    def _send_discord(self, alert):
        """Fire a Discord webhook with the alert."""
        if not self._discord_webhook:
            return

        colors = {
            "critical": 0xE24B4A,
            "high": 0xEF9F27,
            "medium": 0x378ADD,
            "low": 0x5DCAA5,
            "info": 0x888888,
        }
        color = colors.get(alert.severity.value, 0x888888)

        payload = {
            "embeds": [{
                "title": f"[{alert.severity.value.upper()}] {alert.title}",
                "description": alert.change_type,
                "color": color,
                "timestamp": alert.timestamp.isoformat(),
                "fields": [
                    {"name": k, "value": str(v), "inline": True}
                    for k, v in alert.details.items()
                ],
                "footer": {"text": "Project Supernova — Real-Time Guard"},
            }]
        }

        try:
            import urllib.request
            req = urllib.request.Request(
                self._discord_webhook,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            if self._logger:
                self._logger.warning(f"discord_webhook_failed: {e}")

    def get_recent(self, count=100) -> list:
        """Return the most recent alerts."""
        return [a.to_dict() for a in self._alert_history[-count:]]
