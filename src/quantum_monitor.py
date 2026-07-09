import random

class CyberTelXQuantumMonitor:
    def __init__(self):
        # List of insecure/classical ciphers that are vulnerable to quantum harvesting
        self.vulnerable_ciphers = [
            "ECDHE-RSA-AES128-GCM-SHA256",
            "AES256-SHA256",
            "DHE-RSA-AES256-GCM-SHA384"
        ]
        # Post-quantum cryptographic ciphers (NIST compliant)
        self.pqc_compliant_ciphers = [
            "TLS_AES_256_GCM_SHA384_KYBER1024",
            "TLS_CHACHA20_POLY1305_SHA256_KYBER768"
        ]

    def audit_handshake(self, client_hello_cipher, negotiated_cipher):
        """
        Detects TLS handshake downgrade attacks and checks cipher strength
        """
        audit_result = {
            "downgrade_detected": False,
            "quantum_vulnerability": "LOW",
            "reason": ""
        }
        
        # Check if client hello proposed Kyber (PQC) but negotiation fell back to RSA/ECC
        pqc_proposed = any(c in client_hello_cipher for c in self.pqc_compliant_ciphers) or "KYBER" in client_hello_cipher
        pqc_negotiated = any(c in negotiated_cipher for c in self.pqc_compliant_ciphers) or "KYBER" in negotiated_cipher
        
        if pqc_proposed and not pqc_negotiated:
            audit_result["downgrade_detected"] = True
            audit_result["quantum_vulnerability"] = "CRITICAL"
            audit_result["reason"] = f"Cipher Downgrade detected: Client proposed Kyber but negotiated classical {negotiated_cipher}."
        elif not pqc_negotiated:
            audit_result["quantum_vulnerability"] = "HIGH"
            audit_result["reason"] = f"Vulnerable Classical Cipher negotiated ({negotiated_cipher}). Exposed to Harvest-Now-Decrypt-Later (HNDL)."
        else:
            audit_result["reason"] = f"Quantum Secure connection established using {negotiated_cipher}."
            
        return audit_result

    def detect_hndl_exfiltration(self, netflow_record):
        """
        Monitors exfiltrated bytes and maps against HNDL markers.
        Harvest-Now-Decrypt-Later typically targets bulk DB transfers (mortgage/legal).
        """
        bytes_out = netflow_record.get("bytes_out", 0)
        cipher = netflow_record.get("cipher", "")
        dest_ip = netflow_record.get("dest_ip", "")
        
        is_hndl_suspect = False
        risk_score = 0.0
        
        # Bulk egress (e.g. > 10MB) over vulnerable cipher to external destination
        is_external = not dest_ip.startswith("192.168.") and not dest_ip.startswith("10.")
        is_vulnerable = cipher in self.vulnerable_ciphers or "KYBER" not in cipher
        
        if bytes_out > 10 * 1024 * 1024 and is_external and is_vulnerable:
            is_hndl_suspect = True
            risk_score = 85.0
            reason = f"HNDL alert: Bulk encrypted exfiltration ({bytes_out / (1024*1024):.1f} MB) using classical encryption to external IP {dest_ip}."
        else:
            reason = "No HNDL exfiltration signals detected."
            
        return {
            "hndl_suspicious": is_hndl_suspect,
            "risk_score": risk_score,
            "reason": reason
        }

if __name__ == "__main__":
    monitor = CyberTelXQuantumMonitor()
    
    # 1. Normal TLS
    print("TLS Audit 1 (Kyber):")
    res = monitor.audit_handshake("TLS_AES_256_GCM_SHA384_KYBER1024:AES128-GCM-SHA256", "TLS_AES_256_GCM_SHA384_KYBER1024")
    print(res)
    
    # 2. Downgrade attack
    print("\nTLS Audit 2 (Downgrade Attack):")
    res = monitor.audit_handshake("TLS_AES_256_GCM_SHA384_KYBER1024:AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256")
    print(res)
    
    # 3. HNDL Netflow audit
    print("\nNetflow Audit (Potential HNDL):")
    flow = {
        "bytes_out": 25 * 1024 * 1024, # 25MB exfil
        "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "dest_ip": "203.0.113.45"
    }
    res = monitor.detect_hndl_exfiltration(flow)
    print(res)
