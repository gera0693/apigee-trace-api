import tempfile
import os
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

# Suprimimos warnings de Scapy
warnings.filterwarnings('ignore', message='.*libpcap.*')
warnings.filterwarnings('ignore', message='.*TLS cipher suite.*')

try:
    import logging
    logging.getLogger("scapy").setLevel(logging.ERROR)
    from scapy.all import rdpcap, IP, IPv6, TCP, Raw, load_layer
    HAS_SCAPY = True
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            load_layer("tls")
        from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSCertificate
        try:
            from scapy.layers.tls.all import TLSAlert
        except Exception:
            TLSAlert = None
        HAS_TLS_LAYER = True
    except Exception:
        HAS_TLS_LAYER = False
except Exception:
    HAS_SCAPY = False
    HAS_TLS_LAYER = False

# ---------------- Funciones Auxiliares y Constantes ----------------

TLS_ALERT_DESCRIPTIONS = {
    0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 21: 'decryption_failed',
    22: 'record_overflow', 30: 'decompression_failure', 40: 'handshake_failure', 41: 'no_certificate',
    42: 'bad_certificate', 43: 'unsupported_certificate', 44: 'certificate_revoked', 45: 'certificate_expired',
    46: 'certificate_unknown', 47: 'illegal_parameter', 48: 'unknown_ca', 49: 'access_denied', 50: 'decode_error',
    51: 'decrypt_error', 70: 'protocol_version', 71: 'insufficient_security', 80: 'internal_error',
    86: 'inappropriate_fallback', 90: 'user_canceled', 100: 'no_renegotiation', 109: 'missing_extension',
    110: 'unsupported_extension', 111: 'certificate_unobtainable', 112: 'unrecognized_name',
    113: 'bad_certificate_status_response', 114: 'bad_certificate_hash_value', 115: 'unknown_psk_identity',
    116: 'certificate_required', 120: 'no_application_protocol'
}

TLS_CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA"
}

MAX_TIMESTAMPS_PER_ALERT = 20

def iso_utc(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace('+00:00', 'Z')
    except Exception:
        return ''

def decode_tls_alert(level: int, description: int) -> Dict[str, Any]:
    level_map = {1: 'warning', 2: 'fatal'}
    return {
        'alert_level': level_map.get(level, f'unknown({level})'),
        'alert_description_code': description,
        'alert_description': TLS_ALERT_DESCRIPTIONS.get(description, f'unknown({description})')
    }

# ---------------- Motor de Análisis (PacketAnalyzer) ----------------

class PacketAnalyzer:
    def __init__(self, filepath: str, tls_ports: Optional[List[int]] = None):
        self.filepath = filepath
        self.packets = []
        self.tls_ports = set(tls_ports or [443, 8443, 9443, 10443])
        self.analysis_results = {
            'summary': {}, 'issues': [], 'tcp_analysis': {}, 'tls_analysis': {}, 'http': {}
        }

    def run(self):
        if not HAS_SCAPY:
            return
        try:
            self.packets = rdpcap(self.filepath)
        except Exception:
            return

        self.analyze_tcp_handshake()
        self.analyze_tls()

    def analyze_tcp_handshake(self) -> Dict[str, Any]:
        handshakes = []
        tcp_streams: Dict[str, Dict[str, Any]] = {}
        for packet in self.packets:
            if TCP in packet:
                src = packet[IP].src if IP in packet else (packet[IPv6].src if IPv6 in packet else None)
                dst = packet[IP].dst if IP in packet else (packet[IPv6].dst if IPv6 in packet else None)
                if not src or not dst: continue
                sport = packet[TCP].sport; dport = packet[TCP].dport
                flags = int(packet[TCP].flags)
                key = f"{src}:{sport}->{dst}:{dport}"
                tcp_streams.setdefault(key, {'packets': []})['packets'].append({'time': float(packet.time), 'flags': flags})
        
        for key, data in tcp_streams.items():
            pkts = data['packets'][:10]
            syn = any(p['flags'] == 2 for p in pkts)
            synack = any(p['flags'] == 18 for p in pkts)
            ack = any(p['flags'] == 16 for p in pkts)
            has_rst = any(p['flags'] & 4 for p in pkts)
            has_fin = any(p['flags'] & 1 for p in pkts)
            desc = ''
            if has_rst: desc = 'Connection reset detected.'
            elif not syn: desc = 'No SYN found.'
            elif not synack: desc = 'No SYN-ACK received.'
            elif not ack: desc = 'No ACK sent.'
            
            complete = syn and synack and ack
            handshakes.append({
                'stream': key, 'handshake_complete': complete,
                'issue_description': desc
            })
            
            if not complete:
                self.analysis_results['issues'].append({
                    'severity': 'HIGH', 'type': 'TCP_HANDSHAKE_INCOMPLETE',
                    'stream': key, 'description': desc
                })

        self.analysis_results['tcp_analysis'] = {
            'total_tcp_streams': len(tcp_streams),
            'complete_handshakes': sum(1 for h in handshakes if h['handshake_complete']),
            'failed_handshakes': sum(1 for h in handshakes if not h['handshake_complete'])
        }
        return self.analysis_results['tcp_analysis']

    def analyze_tls(self):
        tls_connections: List[Dict[str, Any]] = []
        tls_details = {'cipher_suites': [], 'tls_versions': [], 'certificates': [], 'handshake_summary': {}, 'alert_summary': {}}
        cipher_names_seen = set(); versions_seen = set()
        
        for pkt in self.packets:
            if TLS not in pkt and TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                if sport not in self.tls_ports and dport not in self.tls_ports: continue
                
            if TLS in pkt:
                src = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else 'Unknown')
                dst = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else 'Unknown')
                sport = pkt[TCP].sport if TCP in pkt else 'Unknown'
                dport = pkt[TCP].dport if TCP in pkt else 'Unknown'
                ts = iso_utc(float(pkt.time))
                record = pkt[TLS]
                msgs = getattr(record, 'msg', []) or []
                
                for m in msgs:
                    info: Dict[str, Any] = {'source': f"{src}:{sport}", 'destination': f"{dst}:{dport}", 'timestamp': ts}
                    rec_ver = getattr(record, 'version', None)
                    if rec_ver is not None:
                        info['tls_version'] = self._parse_tls_version(rec_ver)
                        if info['tls_version'] not in versions_seen:
                            versions_seen.add(info['tls_version'])
                            tls_details['tls_versions'].append(info['tls_version'])
                            
                    if isinstance(m, TLSClientHello):
                        info['handshake_type'] = 'Client Hello'
                    elif isinstance(m, TLSServerHello):
                        info['handshake_type'] = 'Server Hello'
                        cipher_sel = getattr(m, 'cipher', None)
                        if cipher_sel is not None:
                            # Convertimos el valor crudo a entero
                            cipher_int = int(cipher_sel)
                            # Buscamos el nombre en el diccionario, o mostramos el Hexadecimal si no está
                            cipher_name = TLS_CIPHER_SUITES.get(cipher_int, f"Unknown (0x{cipher_int:04x})")
                            
                            info['cipher_suite'] = cipher_name
                            
                            if info['cipher_suite'] not in cipher_names_seen:
                                cipher_names_seen.add(info['cipher_suite'])
                                tls_details['cipher_suites'].append({
                                    'name': info['cipher_suite'], 
                                    'connection': info['destination']
                                })
                    elif isinstance(m, TLSCertificate):
                        info['handshake_type'] = 'Certificate'
                    elif TLSAlert is not None and isinstance(m, TLSAlert):
                        info['handshake_type'] = 'Alert'
                        level = int(getattr(m, 'level', 0)); desc = int(getattr(m, 'description', 0))
                        info.update(decode_tls_alert(level, desc))
                        
                        # Add to summary
                        bucket = tls_details['alert_summary'].setdefault(info['alert_description'], {'count': 0, 'first_seen': None, 'last_seen': None, 'timestamps': []})
                        bucket['count'] += 1
                        if not bucket['first_seen'] or ts < bucket['first_seen']: bucket['first_seen'] = ts
                        if not bucket['last_seen'] or ts > bucket['last_seen']: bucket['last_seen'] = ts
                        if len(bucket['timestamps']) < MAX_TIMESTAMPS_PER_ALERT: bucket['timestamps'].append(ts)
                        
                        if info['alert_level'] == 'fatal':
                            self.analysis_results['issues'].append({'severity':'CRITICAL','type':'TLS_FATAL_ALERT','description': f"[{ts}] Fatal TLS alert: {info['alert_description']} ({desc}) from {info['destination']}"})
                    else:
                        info['handshake_type'] = m.__class__.__name__
                        
                    tls_connections.append(info)

        client_hellos = sum(1 for c in tls_connections if c.get('handshake_type')=='Client Hello')
        server_hellos = sum(1 for c in tls_connections if c.get('handshake_type')=='Server Hello')
        certificates = sum(1 for c in tls_connections if c.get('handshake_type')=='Certificate')
        alerts = sum(1 for c in tls_connections if c.get('handshake_type')=='Alert')
        
        tls_details['handshake_summary'] = {'client_hellos': client_hellos, 'server_hellos': server_hellos, 'certificates': certificates, 'alerts': alerts}
        
        self.analysis_results['tls_analysis'] = {
            'tls_connections_found': len(tls_connections),
            'connections': tls_connections[:10],
            'cipher_suites': tls_details['cipher_suites'],
            'tls_versions': tls_details['tls_versions'],
            'handshake_summary': tls_details['handshake_summary'],
            'alert_summary': tls_details['alert_summary'],
            'wireshark_filters': self._generate_wireshark_filters(tls_connections)
        }

    def _parse_tls_version(self, version_bytes: int) -> str:
        tbl = {0x0300:'SSL 3.0',0x0301:'TLS 1.0',0x0302:'TLS 1.1',0x0303:'TLS 1.2',0x0304:'TLS 1.3'}
        return tbl.get(version_bytes, f'Unknown (0x{version_bytes:04x})')

    def _generate_wireshark_filters(self, connections: List[Dict]) -> Dict[str, str]:
        filters = {
            'all_tls_traffic': {'description': 'Show all TLS/SSL traffic', 'filter': 'tls || ssl'},
            'tls_handshakes': {'description': 'Show only TLS handshake messages', 'filter': 'tls.handshake'},
            'client_hello': {'description': 'Show Client Hello', 'filter': 'tls.handshake.type == 1'},
            'server_hello': {'description': 'Show Server Hello', 'filter': 'tls.handshake.type == 2'},
            'certificates': {'description': 'Show Certificate messages', 'filter': 'tls.handshake.type == 11'},
            'tls_alerts': {'description': 'Show TLS alert messages', 'filter': 'tls.alert_message'},
            'tls_version_12': {'description': 'TLS 1.2 records', 'filter': 'tls.record.version == 0x0303'}
        }
        if connections:
            for conn in connections:
                if 'destination' in conn:
                    dest_ip = conn['destination'].split(':')[0]
                    filters['specific_connection'] = {'description': f'TLS to/from {dest_ip}', 'filter': f'(tls || ssl) && ip.addr == {dest_ip}'}
                    break
        return filters

    def generate_report(self) -> str:
        report = []
        report.append('=' * 80)
        report.append('NETWORK PACKET CAPTURE ANALYSIS REPORT')
        report.append('=' * 80)
        report.append('')
        
        report.append(f'Total Packets Analyzed: {len(self.packets)}')
        tcp = self.analysis_results.get('tcp_analysis', {})
        report.append(f"TCP Streams: {tcp.get('total_tcp_streams', 0)}")
        report.append(f"Complete Handshakes: {tcp.get('complete_handshakes', 0)}")
        report.append(f"Failed Handshakes: {tcp.get('failed_handshakes', 0)}")
        report.append('')
        
        tls = self.analysis_results.get('tls_analysis', {})
        if tls:
            report.append('TLS/SSL ANALYSIS')
            report.append('-' * 80)
            report.append(f"TLS Connections Found: {tls.get('tls_connections_found', 0)}")
            
            if tls.get('tls_versions'):
                report.append('\nTLS Versions Detected:')
                for v in tls['tls_versions']: report.append(f" - {v}")
                
            if tls.get('cipher_suites'):
                report.append('\nNegotiated Cipher Suites:')
                for c in tls['cipher_suites'][:8]:
                    report.append(f" - {c['name']}")
                    report.append(f"   Connection: {c['connection']}")
                    
            if tls.get('handshake_summary'):
                hs = tls['handshake_summary']
                report.append('\nHandshake Summary:')
                report.append(f" Client Hello Messages: {hs.get('client_hellos', 0)}")
                report.append(f" Server Hello Messages: {hs.get('server_hellos', 0)}")
                report.append(f" Certificate Messages: {hs.get('certificates', 0)}")
                report.append(f" Alert Messages: {hs.get('alerts', 0)}")
                
            if tls.get('alert_summary'):
                report.append('\nTLS ALERT SUMMARY (by description)')
                report.append('-' * 80)
                items = sorted(tls['alert_summary'].items(), key=lambda kv: (-kv[1]['count'], kv[0]))
                for desc, meta in items:
                    fs = meta.get('first_seen') or 'n/a'; ls = meta.get('last_seen') or 'n/a'
                    report.append(f" - {desc}: {meta['count']}  (first: {fs}, last: {ls})")
                    ts_list = meta.get('timestamps') or []
                    if ts_list: report.append(f"   timestamps: {', '.join(ts_list)}")
                    
            if tls.get('connections'):
                report.append('\nConnection Details (Sample):')
                for conn in tls['connections']:
                    line = f" - {conn.get('source','?')} → {conn.get('destination','?')}"
                    if conn.get('timestamp'): line += f" | {conn['timestamp']}"
                    if conn.get('handshake_type'): line += f" | {conn['handshake_type']}"
                    if conn.get('tls_version'): line += f" | {conn['tls_version']}"
                    report.append(line)
                    
            if tls.get('wireshark_filters'):
                report.append('\nRECOMMENDED WIRESHARK FILTERS:')
                report.append('-' * 80)
                for name, finfo in list(tls['wireshark_filters'].items()):
                    report.append(f"{finfo['description']}:")
                    report.append(f"  {finfo['filter']}\n")
                    
        report.append('\nISSUES DETECTED')
        report.append('-' * 80)
        issues = self.analysis_results.get('issues', [])
        if issues:
            for issue in issues:
                report.append(f"[{issue.get('severity','INFO')}] {issue.get('type','')}: {issue.get('description','')}")
        else:
            report.append("NO CRITICAL ISSUES DETECTED")
            
        report.append('')
        report.append('=' * 80)
        report.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append('=' * 80)
        
        return '\n'.join(report)

# ---------------- Función Principal de Entrada ----------------

def analyze_pcap(content: bytes) -> Dict[str, Any]:
    analysis = {
        "status": "ok",
        "request": {},
        "metadata": {
            "organization": "-", "environment": "-", "api": "-", "revision": "-",
            "sessionId": "-", "retrieved": "-", "virtualhost": "-", "proxyUrl": "-"
        },
        "stateChanges": [], "policies": [], "performance": {}, "issues": [],
        "causes": [], "remediations": [], "playbooks": [], "report_text": ""
    }

    # Guardar archivo temporalmente para que Scapy/rdpcap lo lea
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Usar el motor encapsulado de análisis avanzado
        analyzer = PacketAnalyzer(filepath=tmp_path)
        analyzer.run()
        
        # Generar el bloque de texto con el formato deseado
        analysis["report_text"] = analyzer.generate_report()
        
        # Opcional: Popular issues en el json por si el frontend los usa
        analysis["issues"] = analyzer.analysis_results.get('issues', [])
        
    finally:
        os.remove(tmp_path)

    return analysis