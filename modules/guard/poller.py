"""Guard poller — periodic AD state polling via APScheduler."""

from apscheduler.schedulers.background import BackgroundScheduler
from modules.guard.change_detector import ChangeDetector
from modules.guard.alert_manager import AlertManager


class GuardPoller:
    def __init__(self, ldap_client, config, logger=None):
        self.ldap = ldap_client
        self._cfg = config.get("guard", {})
        self._logger = logger
        self.detector = ChangeDetector(ldap_client)
        self.alert_manager = AlertManager(config, logger=logger)
        self._scheduler = BackgroundScheduler()
        self._running = False
        self._events_analysed = 0
        self._alerts_triggered = 0
        self._start_time = None

    def start(self):
        """Take baseline and begin periodic polling."""
        if self._running:
            return

        from datetime import datetime, timezone
        self._start_time = datetime.now(timezone.utc)
        self.detector.take_baseline()
        self._running = True

        interval = self._cfg.get("poll_interval_seconds", 60)
        self._scheduler.add_job(
            self._poll,
            "interval",
            seconds=interval,
            id="guard_poll",
            replace_existing=True,
        )
        self._scheduler.start()

        if self._logger:
            self._logger.info("guard_started", extra_data={"interval_seconds": interval})

    def stop(self):
        """Stop polling."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
        self._running = False
        if self._logger:
            self._logger.info("guard_stopped")

    def _poll(self):
        """Execute one polling cycle."""
        try:
            alerts = self.detector.poll()
            self._events_analysed += 1
            if alerts:
                processed = self.alert_manager.process(alerts)
                self._alerts_triggered += len(processed)
                if self._logger:
                    self._logger.info(
                        "guard_alerts",
                        extra_data={"count": len(processed)},
                    )
        except Exception as e:
            if self._logger:
                self._logger.error(f"guard_poll_error: {e}")

    @property
    def status(self) -> dict:
        """Return current guard status."""
        from datetime import datetime, timezone
        uptime_seconds = 0
        if self._start_time:
            uptime_seconds = int((datetime.now(timezone.utc) - self._start_time).total_seconds())

        threat = "low"
        if self._alerts_triggered > 5:
            threat = "high"
        elif self._alerts_triggered > 0:
            threat = "medium"

        return {
            "running": self._running,
            "threat_level": threat,
            "events_analysed": self._events_analysed,
            "alerts_triggered": self._alerts_triggered,
            "uptime_seconds": uptime_seconds,
            "recent_alerts": self.alert_manager.get_recent(20),
        }
