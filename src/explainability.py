class CyberTelXExplainability:
    def __init__(self):
        pass
        
    def generate_narrative(self, alert):
        """
        Synthesizes alert data, GNN risk factors, and SHAP features into a
        plain-English narrative explaining the threat scenario.
        """
        user_id = alert.get("user_id", "Unknown User")
        event_type = alert.get("event_type", "ANOMALY")
        risk_score = alert.get("risk_score", 0.0)
        reasons = alert.get("reasons", [])
        shap_values = alert.get("shap_values", {})
        
        # Format the top SHAP features
        sorted_shap = sorted(shap_values.items(), key=lambda x: x[1], reverse=True)
        top_features_str = ", ".join([f"{feat} ({val}%)" for feat, val in sorted_shap[:3]])
        
        narrative = (
            f"Alert is flagged as {self._get_severity(risk_score)} (Risk Score: {risk_score}/100) "
            f"for user account {user_id}.\n\n"
            f"Explainability Analysis:\n"
            f"• Primary Drivers: {top_features_str}.\n"
            f"• Detailed Path Correlation: "
        )
        
        # Custom logic based on reasons
        if reasons:
            narrative += " ".join(reasons)
        else:
            narrative += f"The cross-domain evaluation engine detected unusual activity patterns in transaction logs paired with minor SIEM authentication alerts."
            
        return narrative
        
    def _get_severity(self, score):
        if score >= 85.0:
            return "CRITICAL"
        elif score >= 70.0:
            return "HIGH"
        elif score >= 40.0:
            return "MEDIUM"
        return "LOW"

if __name__ == "__main__":
    xai = CyberTelXExplainability()
    
    mock_alert = {
        "user_id": "USR_1002",
        "event_type": "ACCOUNT_TAKEOVER",
        "risk_score": 92.5,
        "reasons": [
            "User login from untrusted/rogue device: DEV_ROUE_9999.",
            "Outbound transfer to high-risk beneficiary account ACC_EXFIL_8888.",
            "Large transfer size of $45000 exceeds behavioral baseline."
        ],
        "shap_values": {
            "New device login": 85,
            "Geo anomaly score": 72,
            "Session velocity": 65,
            "Transaction amount": 58,
            "Failed auth attempts": 92
        }
    }
    
    narrative = xai.generate_narrative(mock_alert)
    print(narrative)
