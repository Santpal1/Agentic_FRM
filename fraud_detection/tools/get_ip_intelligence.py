"""
Tool: get_ip_intelligence (Stage 2 - IP Reputation and Geolocation)
Returns VPN/proxy/datacenter detection, country mismatch, historical fraud from this IP and /24 subnet.
FIX-1: f_datacenter_ip uses two-layer check (isp string + CIDR prefix fallback).
"""

from mcp import types
from fraud_detection.utils import get_db
from fraud_detection.datacenter_detection import _is_datacenter_ip

async def get_ip_intelligence(args):
    """
    STAGE 2 — IP reputation and geolocation intelligence.
    Returns: VPN/proxy/datacenter detection, country mismatch, historical fraud from this IP and /24 subnet.
    FIX-1: f_datacenter_ip uses two-layer check (isp string + CIDR prefix fallback).
    """
    ip=args.get('ip',''); ipc=args.get('ip_country_long',''); isc=args.get('issuerCountryCode','')
    if not ip: return [types.TextContent(type="text", text="ip is required")]
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT COUNT(*) AS tt,SUM(is_fraud) AS ft,AVG(is_fraud) AS fr,
            COUNT(DISTINCT card_number) AS uc,COUNT(DISTINCT email) AS ue,
            MAX(f_datacenter_ip) AS dc,GROUP_CONCAT(DISTINCT ip_country) AS ctry,
            MIN(purchase_date) AS fs,MAX(purchase_date) AS ls
            FROM transactions WHERE ip=%s""",(ip,))
        irow=cur.fetchone()
        subnet='.'.join(ip.split('.')[:3])+'%'
        cur.execute("""SELECT COUNT(*) AS st,SUM(is_fraud) AS sf,AVG(is_fraud) AS sfr,
            COUNT(DISTINCT ip) AS sui FROM transactions WHERE ip LIKE %s AND ip!=%s""",(subnet,ip))
        srow=cur.fetchone()
        ipfr=float(irow['fr'] or 0)*100 if irow and irow['tt'] else None
        sfr=float(srow['sfr'] or 0)*100 if srow and srow['st'] else None
        mismatch=ipc and isc and ipc!='India' and isc=='IND'
        # FIX-1: use two-layer detection for the IP intel report too
        dc = _is_datacenter_ip(ip, '')   # isp not available here; CIDR fallback covers it
        risks=[]
        if mismatch:            risks.append("IP country ≠ issuer country")
        if dc:                  risks.append("Datacenter/cloud/Tor IP (CIDR prefix match)")
        if (ipfr or 0)>20:     risks.append(f"High IP fraud rate ({ipfr:.0f}%)")
        if (sfr or 0)>20:      risks.append(f"High subnet fraud rate ({sfr:.0f}%)")
        if irow and (irow['uc'] or 0)>5: risks.append("Many cards seen from this IP")
        lines=[f"IP INTELLIGENCE REPORT  [STAGE 2]","="*60,
               f"IP address       : {ip}",f"Reported country : {ipc or 'N/A'}",
               f"Issuer country   : {isc or 'N/A'}",
               f"Country mismatch : {'[!] YES' if mismatch else 'no'}",
               f"Datacenter IP    : {'[!] YES — CIDR prefix match' if dc else 'no'}",""]
        if irow and irow['tt']:
            lines+=[f"IP HISTORY",f"  Total txns   : {irow['tt']}",
                    f"  Fraud txns   : {int(irow['ft'] or 0)}  ({ipfr:.1f}%)",
                    f"  Unique cards : {irow['uc']}",f"  Unique emails: {irow['ue']}",
                    f"  Countries    : {irow['ctry']}",""]
        else: lines+=["IP HISTORY       : First-seen — no prior history",""]
        if srow and srow['st']:
            lines+=[f"SUBNET /24",f"  Txns: {srow['st']}  Fraud rate: {sfr:.1f}%  Unique IPs: {srow['sui']}",""]
        lines+=[f"RISK INDICATORS ({len(risks)})",
                f"  {(chr(10)+'  ').join(risks) if risks else 'none'}","",
                f"ANALYST GUIDANCE",
                f"  {'HIGH RISK — weight heavily toward fraud.' if len(risks)>=2 else 'MODERATE — one indicator present.' if risks else 'CLEAN — no IP-level risk signals.'}"]
        return [types.TextContent(type="text", text='\n'.join(lines))]
    finally: cur.close(); db.close()
