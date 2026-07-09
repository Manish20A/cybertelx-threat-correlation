// Sample pre-populated alerts matching the simulator scenarios
const mockAlerts = [
    {
        id: "ALT-4871",
        user_id: "USR_1002",
        type: "Account Takeover Attempt",
        score: 94,
        sev: "CRITICAL",
        time: "14:27:03 UTC",
        narrative: '"This alert is driven by 5 failed authentication attempts followed by a successful login from a previously unseen device in a high-risk geography, 90 seconds before a $47,500 international wire transfer was initiated to beneficiary ACC_EXFIL_8888."',
        shap: [
            { label: "Failed auth attempts", val: 92, color: "#ff4c4c" },
            { label: "New device login", val: 85, color: "#00d4c8" },
            { label: "Geo anomaly score", val: 72, color: "#008cff" },
            { label: "Session velocity", val: 65, color: "#ff8c00" },
            { label: "Transaction amount", val: 58, color: "#8b5cf6" }
        ],
        crypto: "Downgrade Attack Flagged: Client proposed PQC TLS_AES_256_GCM_SHA384_KYBER1024 but server forced negotiation down to classical ECDHE-RSA-AES128-GCM-SHA256. Risk level evaluated as CRITICAL.",
        graphNodes: [
            { id: "USR_1002", type: "user", x: 300, y: 150, name: "USR_1002" },
            { id: "DEV_ROUE_9999", type: "dev", x: 200, y: 280, name: "DEV_ROUE_9999", alert: true },
            { id: "203.0.113.5", type: "ip", x: 400, y: 280, name: "203.0.113.5", alert: true },
            { id: "ACC_5003", type: "acc", x: 300, y: 50, name: "ACC_5003" },
            { id: "ACC_EXFIL_8888", type: "acc", x: 480, y: 100, name: "ACC_EXFIL_8888", alert: true }
        ],
        graphEdges: [
            { from: "USR_1002", to: "DEV_ROUE_9999", rel: "LOGGED_IN_ON" },
            { from: "USR_1002", to: "203.0.113.5", rel: "IP_ADDRESS" },
            { from: "USR_1002", to: "ACC_5003", rel: "OWNS" },
            { from: "ACC_5003", to: "ACC_EXFIL_8888", rel: "TRANSFERRED_TO", alert: true }
        ]
    },
    {
        id: "ALT-2938",
        user_id: "ADMIN_MGR_01",
        type: "Insider Threat Exfiltration",
        score: 82,
        sev: "HIGH",
        time: "15:02:11 UTC",
        narrative: '"DB admin executed a database dump containing 10,000+ customer records at 2:00 AM outside of standard operations window, followed by a bulk egress exfiltration of 62MB to a foreign storage IP."',
        shap: [
            { label: "Query volume anomaly", val: 89, color: "#ff8c00" },
            { label: "Operation hour shift", val: 78, color: "#ffc000" },
            { label: "Egress volume egress", val: 70, color: "#8b5cf6" },
            { label: "Role baseline deviation", val: 55, color: "#008cff" }
        ],
        crypto: "Harvest-Now-Decrypt-Later (HNDL) Vulnerability Risk: Data transfer of 62.4MB encrypted with vulnerable cipher Suite ECDHE-RSA-AES128-GCM-SHA256 to external IP. Risk level evaluated as HIGH.",
        graphNodes: [
            { id: "ADMIN_MGR_01", type: "user", x: 300, y: 150, name: "Admin Mgr 1" },
            { id: "DEV_ADMIN_WS", type: "dev", x: 180, y: 180, name: "Admin WS" },
            { id: "CORE_CUSTOMER_DB", type: "acc", x: 300, y: 50, name: "Customer DB" },
            { id: "EXTERNAL_IP_STORAGE", type: "ip", x: 450, y: 220, name: "Rogue Egress IP", alert: true }
        ],
        graphEdges: [
            { from: "ADMIN_MGR_01", to: "DEV_ADMIN_WS", rel: "LOGGED_IN" },
            { from: "ADMIN_MGR_01", to: "CORE_CUSTOMER_DB", rel: "SENSITIVE_QUERY" },
            { from: "CORE_CUSTOMER_DB", to: "EXTERNAL_IP_STORAGE", rel: "BULK_TRANSFER", alert: true }
        ]
    },
    {
        id: "ALT-1204",
        user_id: "USR_1009",
        type: "Card-Not-Present Fraud Ring",
        score: 55,
        sev: "MEDIUM",
        time: "15:19:45 UTC",
        narrative: '"Unusual pattern of low-value card transactions on 3 dormant customer accounts originating from the same /24 IP network range within a 12-minute window."',
        shap: [
            { label: "IP range sharing", val: 68, color: "#ffc000" },
            { label: "Account dormancy", val: 61, color: "#008cff" },
            { label: "Transaction cadence", val: 49, color: "#00d4c8" }
        ],
        crypto: "Classical cipher negotiation used. PQC Kyber cipher was disabled on card reader endpoint. Risk level evaluated as MEDIUM.",
        graphNodes: [
            { id: "USR_1009", type: "user", x: 300, y: 150, name: "USR_1009" },
            { id: "192.168.1.18", type: "ip", x: 200, y: 250, name: "192.168.1.18" },
            { id: "ACC_5009", type: "acc", x: 300, y: 50, name: "ACC_5009" },
            { id: "MERCHANT_XYZ", type: "acc", x: 420, y: 120, name: "Merchant XYZ", alert: true }
        ],
        graphEdges: [
            { from: "USR_1009", to: "192.168.1.18", rel: "LOGGED_IN" },
            { from: "USR_1009", to: "ACC_5009", rel: "OWNS" },
            { from: "ACC_5009", to: "MERCHANT_XYZ", rel: "PAYMENT", alert: true }
        ]
    }
];

let selectedAlertId = null;

// Initialize Dashboard
document.addEventListener("DOMContentLoaded", () => {
    renderAlertsQueue();
    startLiveLogFeed();
    resetGraph();
});

// Render Alert List
function renderAlertsQueue() {
    const queue = document.getElementById("alerts-queue");
    queue.innerHTML = "";
    document.getElementById("alert-count").innerText = `${mockAlerts.length} Alerts`;
    
    mockAlerts.forEach(alert => {
        const item = document.createElement("div");
        item.className = `alert-item ${alert.id === selectedAlertId ? 'selected' : ''}`;
        item.onclick = () => selectAlert(alert.id);
        
        item.innerHTML = `
            <div class="alert-info">
                <h4>${alert.type}</h4>
                <div class="alert-meta">User: ${alert.user_id} | ${alert.time}</div>
            </div>
            <span class="alert-badge ${alert.sev.toLowerCase()}">${alert.score} Risk</span>
        `;
        queue.appendChild(item);
    });
}

// Select an alert
function selectAlert(id) {
    selectedAlertId = id;
    renderAlertsQueue();
    
    const alert = mockAlerts.find(a => a.id === id);
    if (!alert) return;
    
    // UI Panel Changes
    document.getElementById("no-selection-panel").classList.add("hide");
    const detailPanel = document.getElementById("detail-panel");
    detailPanel.classList.remove("hide");
    
    // Load Details
    document.getElementById("detail-risk-val").innerText = alert.score;
    document.getElementById("detail-user-id").innerText = alert.type;
    document.getElementById("detail-alert-id").innerText = `Alert ID: ${alert.id} | Timestamp: ${alert.time}`;
    
    const sevBadge = document.getElementById("detail-sev");
    sevBadge.innerText = alert.sev;
    sevBadge.className = `badge detail-sev-badge ${alert.sev.toLowerCase()}`;
    
    const ring = document.querySelector(".risk-ring");
    const colorMap = { CRITICAL: "#ff4c4c", HIGH: "#ff8c00", MEDIUM: "#ffc000" };
    ring.style.borderColor = colorMap[alert.sev];
    ring.style.boxShadow = `0 0 15px ${alert.sev === 'CRITICAL' ? 'rgba(255, 76, 76, 0.25)' : 'rgba(255, 140, 0, 0.2)'}`;
    
    document.getElementById("detail-narrative-text").innerText = alert.narrative;
    document.getElementById("crypto-audit-text").innerText = alert.crypto;
    
    // Render SHAP Bars
    const shapContainer = document.getElementById("shap-bars");
    shapContainer.innerHTML = "";
    alert.shap.forEach(item => {
        const row = document.createElement("div");
        row.className = "shap-row";
        row.innerHTML = `
            <span class="shap-label">${item.label}</span>
            <div class="shap-track">
                <div class="shap-bar" style="width: ${item.val}%; background-color: ${item.color}"></div>
            </div>
            <span class="shap-val" style="color: ${item.color}">${item.val}%</span>
        `;
        shapContainer.appendChild(row);
    });
    
    // Render the selected Alert Graph
    renderGraph(alert.graphNodes, alert.graphEdges);
}

// Reset graph view to default full topology
function resetGraph() {
    const defaultNodes = [
        { id: "USR_MAIN", type: "user", x: 300, y: 200, name: "SOC Analyst Workspace" },
        { id: "SIEM_LOGS", type: "ip", x: 180, y: 120, name: "SIEM Engine" },
        { id: "CORE_BANK", type: "acc", x: 420, y: 120, name: "Core Banking API" },
        { id: "PQC_SENTINEL", type: "dev", x: 300, y: 80, name: "PQC Sentinel" }
    ];
    const defaultEdges = [
        { from: "USR_MAIN", to: "SIEM_LOGS", rel: "MONITORS" },
        { from: "USR_MAIN", to: "CORE_BANK", rel: "AUDITS" },
        { from: "SIEM_LOGS", to: "PQC_SENTINEL", rel: "FEED" },
        { from: "CORE_BANK", to: "PQC_SENTINEL", rel: "VERIFIES" }
    ];
    
    selectedAlertId = null;
    renderAlertsQueue();
    document.getElementById("no-selection-panel").classList.remove("hide");
    document.getElementById("detail-panel").classList.add("hide");
    
    renderGraph(defaultNodes, defaultEdges);
}

// Render dynamic graph inside SVG
function renderGraph(nodes, edges) {
    const svg = document.getElementById("network-graph");
    svg.innerHTML = ""; // clear previous elements
    
    // Create definition markers for arrow heads
    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    defs.innerHTML = `
        <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#3a3f5c" />
        </marker>
        <marker id="arrow-alert" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#ff4c4c" />
        </marker>
    `;
    svg.appendChild(defs);
    
    // Draw connection edges
    edges.forEach(edge => {
        const fromNode = nodes.find(n => n.id === edge.from);
        const toNode = nodes.find(n => n.id === edge.to);
        if (!fromNode || !toNode) return;
        
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", fromNode.x);
        line.setAttribute("y1", fromNode.y);
        line.setAttribute("x2", toNode.x);
        line.setAttribute("y2", toNode.y);
        
        if (edge.alert) {
            line.setAttribute("stroke", "#ff4c4c");
            line.setAttribute("stroke-width", "2");
            line.setAttribute("stroke-dasharray", "4,4");
            line.setAttribute("marker-end", "url(#arrow-alert)");
        } else {
            line.setAttribute("stroke", "#3a3f5c");
            line.setAttribute("stroke-width", "1.2");
            line.setAttribute("marker-end", "url(#arrow)");
        }
        svg.appendChild(line);
        
        // Relationship label
        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", (fromNode.x + toNode.x) / 2);
        text.setAttribute("y", (fromNode.y + toNode.y) / 2 - 5);
        text.setAttribute("font-size", "7.5px");
        text.setAttribute("fill", edge.alert ? "#ff4c4c" : "#94a3b8");
        text.setAttribute("text-anchor", "middle");
        text.textContent = edge.rel;
        svg.appendChild(text);
    });
    
    // Draw nodes
    nodes.forEach(node => {
        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        g.setAttribute("style", "cursor: pointer;");
        g.onclick = () => {
            // If user node clicked and we have a mock alert matching, open it
            const matched = mockAlerts.find(a => a.user_id === node.id);
            if (matched) selectAlert(matched.id);
        };
        
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", node.x);
        circle.setAttribute("cy", node.y);
        circle.setAttribute("r", node.alert ? "16" : "12");
        
        // Node styling based on type
        const colorMap = {
            user: "#008cff",
            ip: "#8b5cf6",
            dev: "#ff8c00",
            acc: "#00d4c8"
        };
        circle.setAttribute("fill", colorMap[node.type] || "#ffffff");
        
        if (node.alert) {
            circle.setAttribute("stroke", "#ff4c4c");
            circle.setAttribute("stroke-width", "3");
            circle.setAttribute("class", "alert-pulse");
        } else {
            circle.setAttribute("stroke", "rgba(255,255,255,0.1)");
            circle.setAttribute("stroke-width", "1.5");
        }
        g.appendChild(circle);
        
        // Node labels
        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", node.x);
        text.setAttribute("y", node.y + (node.alert ? 28 : 22));
        text.setAttribute("font-size", "9px");
        text.setAttribute("font-weight", "600");
        text.setAttribute("fill", "#ffffff");
        text.setAttribute("text-anchor", "middle");
        text.textContent = node.name;
        g.appendChild(text);
        
        svg.appendChild(g);
    });
}

// Simulated Ingestion Feed Terminal Logs
function startLiveLogFeed() {
    const terminal = document.getElementById("log-terminal");
    const channels = ["telemetry", "transaction", "quantum"];
    const actions = {
        telemetry: [
            "SIEM_LOGIN: USR_1044 successful login from DEV_2441.",
            "SIEM_LOGIN: USR_1082 failed authentication on DEV_ROUE_8812.",
            "API_REQUEST: USR_1002 authorized request /api/v1/payments.",
            "EDR_ALERT: DEV_2933 system integrity check passed."
        ],
        transaction: [
            "BANK_TRANSFER: ACC_5021 transferred $120.00 to ACC_5029 (MOBILE_APP).",
            "BANK_TRANSFER: ACC_5002 transferred $1,450.00 to ACC_5007 (WEB_PORTAL).",
            "CARD_PAYMENT: ACC_5045 payment of $34.50 approved at MERCHANT_WAL.",
            "BANK_TRANSFER: ACC_5003 transfer of $250.00 processed."
        ],
        quantum: [
            "PQC_SENTINEL: Negotiated Kyber-1024 handshake on TLS gateway endpoint.",
            "PQC_SENTINEL: HNDL audit baseline scan completed. No exfiltrations.",
            "PQC_SENTINEL: Cipher check: AES-256-GCM evaluated. Harvest-Now-Decrypt-Later exposure LOW."
        ]
    };
    
    setInterval(() => {
        const type = channels[Math.floor(Math.random() * channels.length)];
        const messages = actions[type];
        const msg = messages[Math.floor(Math.random() * messages.length)];
        
        const timestamp = new Date().toISOString().split("T")[1].slice(0, 8);
        const line = document.createElement("div");
        line.className = `log-line ${type}`;
        line.innerHTML = `
            <span class="log-time">[${timestamp}]</span>
            <span class="log-msg">${msg}</span>
        `;
        
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
        
        // Clean old logs if exceeding 50 lines to keep performance high
        if (terminal.childElementCount > 50) {
            terminal.removeChild(terminal.firstElementChild);
        }
        
        // Randomly simulate traffic numbers variance
        const trafficValue = Math.floor(2300000 + Math.random() * 15000);
        document.getElementById("kpi-eps").innerText = trafficValue.toLocaleString();
    }, 1500);
}
