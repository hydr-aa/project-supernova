"""Safety interlocks — authorization gate and operational boundaries."""


def request_authorization(config, logger) -> bool:
    """
    Return True if the operator authorises the scan.

    In production, this prompts the user via the dashboard API.
    In dev/test mode, reads SUPERNOVA_AUTHORIZED=1 from the environment.
    """
    import os

    if os.environ.get("SUPERNOVA_AUTHORIZED") == "1":
        logger.info("authorization_granted", extra_data={"source": "environment"})
        return True

    domain = config.get("ldap", {}).get("domain", "unknown")
    network = config.get("network", {}).get("target_network", "unknown")

    logger.info(
        "authorization_required",
        extra_data={"domain": domain, "network": network},
    )

    # In headless mode, refuse without explicit authorization
    return False
