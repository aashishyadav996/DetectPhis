"""
DNS resolution and IP infrastructure analysis.
Performs socket-level A/AAAA record resolution, SSRF risk checking
(RFC 1918 private IPs, loopback, cloud metadata), and reverse DNS pointer lookups.
"""
import ipaddress
import socket
from typing import Any

DEFAULT_DNS_TIMEOUT = 2.5


def resolve_host_infrastructure(hostname: str, timeout: float = DEFAULT_DNS_TIMEOUT) -> dict[str, Any]:
    """
    Resolves the provided hostname to IP addresses and evaluates infrastructure risks.
    Gracefully handles offline environments and unresolvable hostnames without raising exceptions.
    """
    if not hostname:
        return {
            "resolved": False,
            "ips": [],
            "ssrf_risk": False,
            "is_fast_flux": False,
            "error": "Hostname is empty.",
        }

    # Check if hostname is already a raw IP address
    try:
        parsed_ip = ipaddress.ip_address(hostname)
        is_private = parsed_ip.is_private
        is_loopback = parsed_ip.is_loopback
        is_link_local = parsed_ip.is_link_local
        ssrf_risk = is_private or is_loopback or is_link_local

        return {
            "resolved": True,
            "ips": [
                {
                    "ip": str(parsed_ip),
                    "version": parsed_ip.version,
                    "is_private": is_private,
                    "is_loopback": is_loopback,
                    "is_link_local": is_link_local,
                    "reverse_host": None,
                }
            ],
            "ssrf_risk": ssrf_risk,
            "is_fast_flux": False,
            "error": None,
        }
    except ValueError:
        pass  # Not a raw IP, proceed with standard DNS lookup

    orig_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        # Resolve A and AAAA records
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        unique_ips: dict[str, dict[str, Any]] = {}

        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]

            if ip_str in unique_ips:
                continue

            try:
                ip_obj = ipaddress.ip_address(ip_str)
                is_priv = ip_obj.is_private
                is_loop = ip_obj.is_loopback
                is_link = ip_obj.is_link_local

                reverse_host = None
                try:
                    host_info = socket.gethostbyaddr(ip_str)
                    reverse_host = host_info[0] if host_info else None
                except (socket.herror, socket.gaierror, socket.timeout, OSError):
                    reverse_host = None

                unique_ips[ip_str] = {
                    "ip": ip_str,
                    "version": ip_obj.version,
                    "is_private": is_priv,
                    "is_loopback": is_loop,
                    "is_link_local": is_link,
                    "reverse_host": reverse_host,
                }
            except ValueError:
                continue

        ip_list = list(unique_ips.values())
        has_ssrf_risk = any(ip["is_private"] or ip["is_loopback"] or ip["is_link_local"] for ip in ip_list)
        is_fast_flux = len(ip_list) >= 4

        return {
            "resolved": len(ip_list) > 0,
            "ips": ip_list,
            "ssrf_risk": has_ssrf_risk,
            "is_fast_flux": is_fast_flux,
            "error": None if ip_list else "DNS resolution returned no records.",
        }

    except socket.gaierror as exc:
        return {
            "resolved": False,
            "ips": [],
            "ssrf_risk": False,
            "is_fast_flux": False,
            "error": f"DNS resolution failed: {exc.strerror or str(exc)}",
        }
    except (socket.timeout, TimeoutError):
        return {
            "resolved": False,
            "ips": [],
            "ssrf_risk": False,
            "is_fast_flux": False,
            "error": "DNS resolution timed out.",
        }
    except Exception as exc:
        return {
            "resolved": False,
            "ips": [],
            "ssrf_risk": False,
            "is_fast_flux": False,
            "error": f"Unexpected error during DNS resolution: {exc}",
        }
    finally:
        socket.setdefaulttimeout(orig_timeout)
