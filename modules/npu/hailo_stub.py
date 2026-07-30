"""Hailo-8 NPU stub — returns CPU-only results when accelerator is not present.

When the Hailo-8 is installed and configured, replace this module with
hailo_inference.py that calls the HailoRT runtime.
"""


class NPUInference:
    """No-op NPU inference that returns safe defaults."""

    def __init__(self, config):
        self._enabled = config.get("npu", {}).get("enabled", False)

    @property
    def available(self) -> bool:
        return self._enabled

    def score_anomaly(self, telemetry_vector: list[float]) -> dict:
        """Return a placeholder anomaly score."""
        return {
            "anomaly_score": 0.0,
            "confidence": 0.0,
            "mode": "stub",
        }

    def score_risk(self, findings: list) -> list:
        """Return findings unchanged (no NPU re-scoring)."""
        return findings
