"""
Datacenter and proxy IP detection. FIX-1: Two-layer approach using ip_isp string match and CIDR prefix fallback.
"""

# FIX-1: Known datacenter/Tor CIDR prefix table for fallback when ip_isp absent
DATACENTER_PREFIXES = (
    # AWS us-east / us-west / ap-southeast
    "52.",   "54.",   "18.",
    # GCP global egress
    "34.",   "35.",   "104.196.", "104.197.", "104.198.", "104.199.",
    # Azure
    "40.",   "20.",   "13.",
    # DigitalOcean
    "134.122.", "137.184.", "143.198.", "146.190.", "159.65.", "159.89.",
    "161.35.",  "164.90.",  "165.22.",  "167.71.",  "167.172.", "174.138.",
    # Linode / Akamai
    "139.162.", "172.104.", "192.46.",  "45.33.",   "45.56.",   "45.79.",
    # Vultr
    "45.32.",   "45.63.",   "45.76.",   "45.77.",
    # OVH
    "51.75.",   "51.77.",   "51.91.",   "54.36.",   "54.38.",
    # Hetzner
    "78.46.",   "88.198.",  "95.216.",  "116.202.", "136.243.",
    # Known Tor exit ranges
    "185.220.", "199.249.", "204.13.",  "192.42.",  "176.10.",
    # Cloudflare Workers / proxies
    "104.16.",  "104.17.",  "104.18.",  "104.19.",  "104.20.",  "104.21.",
    "172.64.",  "172.65.",  "172.66.",  "172.67.",
)

def _is_datacenter_ip(ip: str, isp: str) -> bool:
    """
    FIX-1: Two-layer datacenter detection.
    Layer 1: existing keyword match on ip_isp (unchanged behaviour).
    Layer 2: fallback CIDR prefix check when ip_isp is absent/empty.
    Returns True if either layer fires.
    """
    DATACENTER_ISP_KEYWORDS = [
        'aws', 'amazon', 'google cloud', 'azure', 'digitalocean',
        'linode', 'vultr', 'ovh', 'hetzner',
    ]
    # Layer 1 — isp string match (original logic)
    if isp:
        isp_lower = isp.lower()
        if any(k in isp_lower for k in DATACENTER_ISP_KEYWORDS):
            return True
    # Layer 2 — prefix fallback
    if ip:
        for prefix in DATACENTER_PREFIXES:
            if ip.startswith(prefix):
                return True
    return False
