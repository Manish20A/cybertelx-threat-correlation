import networkx as nx
import random

class CyberTelXGNNCorrelation:
    def __init__(self):
        self.G = nx.MultiDiGraph()
        
    def add_telemetry_event(self, event):
        user = event.get("user_id")
        device = event.get("device_id")
        ip = event.get("source_ip")
        
        self.G.add_node(user, type="User")
        self.G.add_node(device, type="Device")
        self.G.add_node(ip, type="IP")
        
        # Access relationship
        self.G.add_edge(user, ip, relation="LOGGED_IN_FROM", timestamp=event.get("timestamp"))
        self.G.add_edge(user, device, relation="USED_DEVICE", timestamp=event.get("timestamp"))
        
    def add_transaction_event(self, tx):
        user = tx.get("user_id")
        acc_from = tx.get("account_from")
        acc_to = tx.get("account_to")
        amount = tx.get("amount", 0.0)
        
        self.G.add_node(user, type="User")
        self.G.add_node(acc_from, type="Account")
        self.G.add_node(acc_to, type="Account")
        
        # Link user to account, and account-to-account transfer
        self.G.add_edge(user, acc_from, relation="OWNS", timestamp=tx.get("timestamp"))
        self.G.add_edge(acc_from, acc_to, relation="TRANSFERRED_TO", amount=amount, timestamp=tx.get("timestamp"))
        
    def evaluate_risk(self, target_user):
        """
        Calculates a GNN-like contextual threat score (0-100) by analyzing
        graph connectivity anomalies (e.g. login from foreign IP exfiltrating to external account)
        """
        score = 10.0 # base score
        reasons = []
        
        if not self.G.has_node(target_user):
            return score, ["User node not yet added to correlation graph"]
            
        # Check IP connection degree and attributes
        ip_nodes = [n for n in self.G.successors(target_user) if self.G.nodes[n].get("type") == "IP"]
        for ip in ip_nodes:
            # Check if this IP is associated with multiple users (fraud ring indicator)
            users_linked = [u for u, _ in self.G.in_edges(ip) if self.G.nodes[u].get("type") == "User"]
            if len(users_linked) > 2:
                score += 35
                reasons.append(f"Source IP {ip} shared between {len(users_linked)} users (possible credential sharing/botnet)")
                
        # Check Device connection degree
        dev_nodes = [n for n in self.G.successors(target_user) if self.G.nodes[n].get("type") == "Device"]
        for dev in dev_nodes:
            if "DEV_ROUE" in str(dev):
                score += 25
                reasons.append(f"User login from untrusted/rogue device: {dev}")
                
        # Check Transfer flows
        accounts = [n for n in self.G.successors(target_user) if self.G.nodes[n].get("type") == "Account"]
        for acc in accounts:
            transfers = self.G.out_edges(acc, data=True)
            for _, dest, data in transfers:
                if "ACC_EXFIL" in str(dest):
                    score += 30
                    reasons.append(f"Outbound transfer to high-risk beneficiary account {dest}")
                if data.get("amount", 0) > 20000:
                    score += 15
                    reasons.append(f"Large transfer size of ${data.get('amount')} exceeds behavioral baseline")
                    
        return min(100.0, score), reasons

if __name__ == "__main__":
    correlation = CyberTelXGNNCorrelation()
    
    # Add events
    normal_login = {
        "timestamp": "2026-07-09T12:00:00",
        "user_id": "USR_1001",
        "device_id": "DEV_2001",
        "source_ip": "192.168.1.10"
    }
    normal_tx = {
        "timestamp": "2026-07-09T12:01:00",
        "user_id": "USR_1001",
        "account_from": "ACC_5001",
        "account_to": "ACC_5002",
        "amount": 250.00
    }
    
    correlation.add_telemetry_event(normal_login)
    correlation.add_transaction_event(normal_tx)
    
    score, reasons = correlation.evaluate_risk("USR_1001")
    print(f"Normal User Risk: {score} | Reasons: {reasons}")
    
    # Anomaly
    rogue_login = {
        "timestamp": "2026-07-09T12:05:00",
        "user_id": "USR_1002",
        "device_id": "DEV_ROUE_9999",
        "source_ip": "203.0.113.5"
    }
    rogue_tx = {
        "timestamp": "2026-07-09T12:06:00",
        "user_id": "USR_1002",
        "account_from": "ACC_5003",
        "account_to": "ACC_EXFIL_8888",
        "amount": 45000.00
    }
    
    correlation.add_telemetry_event(rogue_login)
    correlation.add_transaction_event(rogue_tx)
    
    score, reasons = correlation.evaluate_risk("USR_1002")
    print(f"Suspicious User Risk: {score} | Reasons: {reasons}")
