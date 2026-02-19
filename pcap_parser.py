from scapy.all import rdpcap, TCP, IP
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
from collections import defaultdict
import tempfile
import os


TLS_VERSION_MAP = {
    769: "TLS 1.0",
    770: "TLS 1.1",
    771: "TLS 1.2",
    772: "TLS 1.3"
}


def analyze_pcap(content: bytes):

    analysis = {
        "status": "ok",
        "request": {},
        "metadata": {
            "organization": "-",
            "environment": "-",
            "api": "-",
            "revision": "-",
            "sessionId": "-",
            "retrieved": "-",
            "virtualhost": "-",
            "proxyUrl": "-"
        },
        "stateChanges": [],
        "policies": [],
        "performance": {},
        "issues": [],
        "causes": [],
        "remediations": [],
        "playbooks": [],
        "report_text": ""
    }

    # Guardar archivo temporal
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    finally:
        os.remove(tmp_path)

    detected_tls = False
    sni_hostname = None
    tls_version_raw = None
    destination_ip = None
    handshake_start = None
    handshake_end = None
    tcp_resets = 0
    retransmissions = 0

    seen_seq = set()

    for pkt in packets:

        # ---------------------------
        # TCP Metrics
        # ---------------------------
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]

            destination_ip = ip.dst

            # Detect TCP Reset
            if tcp.flags & 0x04:
                tcp_resets += 1

            # Detect retransmissions
            key = (ip.src, ip.dst, tcp.sport, tcp.dport, tcp.seq)
            if key in seen_seq:
                retransmissions += 1
            else:
                seen_seq.add(key)

        # ---------------------------
        # TLS Detection
        # ---------------------------
        if pkt.haslayer(TLS):
            detected_tls = True

            # Client Hello
            if pkt.haslayer(TLSClientHello):
                ch = pkt[TLSClientHello]

                if not handshake_start:
                    handshake_start = pkt.time

                # TLS Version
                if hasattr(ch, "version"):
                    tls_version_raw = ch.version

                # Robust SNI extraction
                if hasattr(ch, "ext") and ch.ext:
                    for ext in ch.ext:
                        try:
                            if hasattr(ext, "servernames") and ext.servernames:
                                for name in ext.servernames:
                                    if hasattr(name, "servername"):
                                        sni_hostname = name.servername.decode(errors="ignore")
                        except Exception:
                            pass

            # Server Hello
            if pkt.haslayer(TLSServerHello):
                sh = pkt[TLSServerHello]
                handshake_end = pkt.time

                if hasattr(sh, "version"):
                    tls_version_raw = sh.version

    # ============================
    # TLS Summary
    # ============================

    if detected_tls:

        # Convert TLS version to readable format
        tls_version = TLS_VERSION_MAP.get(tls_version_raw, f"Unknown ({tls_version_raw})")

        handshake_time = None
        if handshake_start and handshake_end:
            handshake_time = round(handshake_end - handshake_start, 4)

        analysis["request"] = {
            "method": "HTTPS",
            "uri": sni_hostname or "Encrypted Traffic",
            "url": f"https://{sni_hostname}" if sni_hostname else "Encrypted",
            "status_code": "Encrypted",
            "reason": "TLS detected",
            "headers": {}
        }

        analysis["metadata"]["virtualhost"] = sni_hostname or "-"
        analysis["metadata"]["proxyUrl"] = f"https://{sni_hostname}" if sni_hostname else "-"

        analysis["performance"] = {
            "tls_version": tls_version,
            "destination_ip": destination_ip,
            "handshake_time_seconds": handshake_time,
            "retransmissions": retransmissions,
            "tcp_resets": tcp_resets
        }

        analysis["issues"].append({
            "severity": "INFO",
            "type": "TLS_ENCRYPTED",
            "code": "TLS",
            "description": "Traffic is encrypted (HTTPS)"
        })

        if tcp_resets > 0:
            analysis["issues"].append({
                "severity": "HIGH",
                "type": "TCP_RESET",
                "code": "RST",
                "description": f"{tcp_resets} TCP reset(s) detected"
            })

        if retransmissions > 5:
            analysis["issues"].append({
                "severity": "MEDIUM",
                "type": "TCP_RETRANSMISSION",
                "code": "RETX",
                "description": f"{retransmissions} TCP retransmissions detected"
            })

        analysis["report_text"] = (
            "PCAP ANALYSIS\n"
            f"TLS Hostname (SNI): {sni_hostname}\n"
            f"TLS Version: {tls_version}\n"
            f"Destination IP: {destination_ip}\n"
            f"Handshake Time: {handshake_time} seconds\n"
            f"Retransmissions: {retransmissions}\n"
            f"TCP Resets: {tcp_resets}\n"
        )

        return analysis

    # ============================
    # No TLS detected
    # ============================

    analysis["request"] = {
        "method": "Unknown",
        "uri": "Unknown",
        "url": "Unknown",
        "status_code": "Unknown",
        "reason": "",
        "headers": {}
    }

    analysis["report_text"] = "No TLS or HTTP detected."

    return analysis
