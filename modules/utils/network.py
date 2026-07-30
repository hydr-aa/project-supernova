"""Network scope verification — ensures the device is on an authorized network."""

import socket


def get_local_ip():
    """Return the primary local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def ip_in_network(ip: str, cidr: str) -> bool:
    """Check if an IP address falls within a CIDR range (e.g. '192.168.70.0/24')."""
    import ipaddress
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)


def verify_network_scope(config, logger) -> bool:
    """Return True if the device's IP is within an authorized network range."""
    local_ip = get_local_ip()
    authorized = config.get("network", {}).get("authorized_networks", [])

    for cidr in authorized:
        if ip_in_network(local_ip, cidr):
            logger.info(
                "network_verified",
                extra_data={"local_ip": local_ip, "cidr": cidr},
            )
            return True

    logger.warning(
        "network_unverified",
        extra_data={"local_ip": local_ip, "authorized": authorized},
    )
    return False
