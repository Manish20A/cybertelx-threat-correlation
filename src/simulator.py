import random
import time
import json
from datetime import datetime

class CyberTelXSimulator:
    def __init__(self):
        self.users = [f"USR_{1000 + i}" for i in range(10)]
        self.devices = [f"DEV_{2000 + i}" for i in range(10)]
        self.ips = [f"192.168.1.{10 + i}" for i in range(10)] + ["203.0.113.5", "198.51.100.72"] # normal + rogue IPs
        self.accounts = [f"ACC_{5000 + i}" for i in range(10)]
        
    def generate_normal_transaction(self):
        user = random.choice(self.users)
        device = random.choice(self.devices)
        ip = random.choice(self.ips[:10]) # normal local IP
        account_from = random.choice(self.accounts)
        account_to = random.choice([acc for acc in self.accounts if acc != account_from])
        amount = round(random.uniform(10.0, 1500.0), 2)
        
        telemetry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "SIEM_LOGIN",
            "user_id": user,
            "device_id": device,
            "source_ip": ip,
            "status": "SUCCESS",
            "threat_indicator": "NONE"
        }
        
        transaction = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "BANK_TRANSFER",
            "user_id": user,
            "account_from": account_from,
            "account_to": account_to,
            "amount": amount,
            "channel": "MOBILE_APP"
        }
        return telemetry, transaction

    def generate_anomaly_scenario(self, scenario_type="ATO"):
        user = random.choice(self.users)
        device = f"DEV_ROUE_{random.randint(9000, 9999)}"
        rogue_ip = random.choice(self.ips[10:]) # suspicious external IP
        account_from = random.choice(self.accounts)
        account_to = f"ACC_EXFIL_{random.randint(8000, 8999)}"
        
        telemetry_events = []
        
        if scenario_type == "ATO": # Account Takeover + Fund Transfer
            # 1. Bruteforce auth logs
            for _ in range(4):
                telemetry_events.append({
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "SIEM_LOGIN",
                    "user_id": user,
                    "device_id": device,
                    "source_ip": rogue_ip,
                    "status": "FAILED",
                    "threat_indicator": "BRUTE_FORCE_SUSPECT"
                })
            # 2. Successful Login
            telemetry_events.append({
                "timestamp": datetime.now().isoformat(),
                "event_type": "SIEM_LOGIN",
                "user_id": user,
                "device_id": device,
                "source_ip": rogue_ip,
                "status": "SUCCESS",
                "threat_indicator": "NEW_DEVICE_GEO_ANOMALY"
            })
            # 3. Sudden Large Transaction
            transaction = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "BANK_TRANSFER",
                "user_id": user,
                "account_from": account_from,
                "account_to": account_to,
                "amount": round(random.uniform(25000.0, 95000.0), 2),
                "channel": "WEB_PORTAL"
            }
            return telemetry_events, transaction
            
        elif scenario_type == "INSIDER": # Admin query + exfil
            telemetry_events.append({
                "timestamp": datetime.now().isoformat(),
                "event_type": "SIEM_PRIVILEGED_QUERY",
                "user_id": "ADMIN_MGR_01",
                "device_id": "DEV_ADMIN_WS",
                "source_ip": "192.168.1.5",
                "status": "SUCCESS",
                "threat_indicator": "MASS_DB_EXPORT_ANOMALY"
            })
            transaction = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "DATA_EXFILTRATION",
                "user_id": "ADMIN_MGR_01",
                "account_from": "CORE_CUSTOMER_DB",
                "account_to": "EXTERNAL_IP_STORAGE",
                "amount": 0.0,
                "bytes_transferred": random.randint(12000000, 85000000)
            }
            return telemetry_events, transaction

if __name__ == "__main__":
    sim = CyberTelXSimulator()
    print("Normal scenario:")
    tel, tx = sim.generate_normal_transaction()
    print("Telemetry:", json.dumps(tel, indent=2))
    print("Transaction:", json.dumps(tx, indent=2))
    
    print("\nAnomaly scenario (Account Takeover):")
    tels, tx_anom = sim.generate_anomaly_scenario("ATO")
    for t in tels:
        print("Telemetry Log:", json.dumps(t, indent=2))
    print("Fraud Transaction:", json.dumps(tx_anom, indent=2))
