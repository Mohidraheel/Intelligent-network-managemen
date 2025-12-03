
from flask import Flask, request, jsonify, render_template, send_from_directory
import re
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

app = Flask(__name__, static_folder='static', template_folder='templates')

# --- Configuration / sample logs ---
SAMPLE_LOGS = """2024-10-25 10:15:23 [CRITICAL] Router-01: High CPU usage detected - 95%
2024-10-25 10:16:45 [WARNING] Switch-03: Port 24 flapping detected
2024-10-25 10:17:12 [INFO] Firewall-01: Configuration backup completed
2024-10-25 10:18:33 [CRITICAL] Server-DB01: Connection timeout - Database unreachable
2024-10-25 10:19:01 [WARNING] Router-02: BGP session down with peer 192.168.1.1
2024-10-25 10:20:15 [INFO] Switch-01: VLAN 100 added successfully
2024-10-25 10:21:47 [CRITICAL] Load-Balancer: Health check failed for backend servers
2024-10-25 10:22:03 [WARNING] Router-01: Memory usage high - 87%
2024-10-25 10:23:10 [INFO] AP-05: Client 7A:3F connected successfully
2024-10-25 10:24:55 [CRITICAL] Server-Web02: Disk space critically low - 98%
2024-10-25 10:25:31 [WARNING] Switch-07: STP topology change detected
2024-10-25 10:26:49 [INFO] VPN-Gateway: New VPN tunnel established with HQ
2024-10-25 10:28:12 [CRITICAL] Core-Router: Packet loss exceeded threshold - 40%
2024-10-25 10:29:37 [WARNING] Firewall-02: High number of dropped packets
2024-10-25 10:31:02 [INFO] Server-Log01: Archive job completed successfully
2024-10-25 10:32:18 [CRITICAL] Switch-02: Power module failure detected
2024-10-25 10:33:44 [WARNING] IDS-01: Suspicious traffic volume detected
2024-10-25 10:35:11 [INFO] Router-03: Firmware upgrade scheduled
2024-10-25 10:36:23 [CRITICAL] Server-Auth: Authentication service down
2024-10-25 10:37:55 [WARNING] Load-Balancer: One backend node slow to respond
2024-10-25 10:38:42 [INFO] Switch-10: LLDP neighbor discovered
2024-10-25 10:39:28 [CRITICAL] Firewall-01: IPS triggered — possible DDoS attack
2024-10-25 10:41:03 [WARNING] AP-03: Weak signal detected for user 5C:22
2024-10-25 10:42:30 [INFO] Router-02: OSPF adjacency formed with 10.0.0.6
2024-10-25 10:43:12 [CRITICAL] Server-DB02: Replication lag exceeded 120 seconds
2024-10-25 10:44:57 [WARNING] Switch-04: Port 7 experiencing errors
2024-10-25 10:46:20 [INFO] Firewall-01: Policy sync completed
Backup completed for Router-01
High CPU usage detected - 92%
VLAN 90 added successfully
Server restarted successfully
"""


# In-memory storage for parsed logs
parsed_logs = []

# Minimal training data for the NB classifier
train_texts = [
    # CRITICAL
    "High CPU usage detected",
    "Connection timeout",
    "Health check failed",
    "Disk space critically low",
    "Packet loss exceeded threshold",
    "Power module failure detected",
    "Authentication service down",
    "Replication lag exceeded",
    "IPS triggered possible DDoS attack",
    "Backend servers unreachable",

    # WARNING
    "Memory usage high",
    "Port flapping detected",
    "BGP session down",
    "STP topology change detected",
    "Dropped packets",
    "Suspicious traffic volume detected",
    "Weak signal detected",
    "Backend node slow to respond",
    "Port experiencing errors",

    # INFO
    "Configuration backup completed",
    "VLAN added successfully",
    "Client connected successfully",
    "VPN tunnel established",
    "Archive job completed successfully",
    "LLDP neighbor discovered",
    "Firmware upgrade scheduled",
    "Policy sync completed",

    # Mixed: logs without severity (still learnable)
    "Backup completed",
    "Server restarted successfully",
    "High CPU usage",
    "VLAN added"
]

train_labels = [
    # CRITICAL (10)
    "CRITICAL",
    "CRITICAL",
    "CRITICAL",
    "CRITICAL",
    "CRITICAL",
    "CRITICAL",
    "CRITICAL",
    "CRITICAL",
    "CRITICAL",
    "CRITICAL",

    # WARNING (9)
    "WARNING",
    "WARNING",
    "WARNING",
    "WARNING",
    "WARNING",
    "WARNING",
    "WARNING",
    "WARNING",
    "WARNING",

    # INFO (8)
    "INFO",
    "INFO",
    "INFO",
    "INFO",
    "INFO",
    "INFO",
    "INFO",
    "INFO",

    # Mixed (fallback labels)
    "INFO",
    "INFO",
    "CRITICAL",
    "INFO"
]


vectorizer = CountVectorizer()
X_train = vectorizer.fit_transform(train_texts)
clf = MultinomialNB()
clf.fit(X_train, train_labels)


# --- Parsing / helper functions ---
def parse_logs(log_text):
    logs = []
    # Accept either full logs with [SEVERITY] or fallback to ML classifier
    pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(.*?)\] (.*?): (.*)'

    for line in log_text.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        match = re.match(pattern, line)
        if match:
            timestamp, severity, device, message = match.groups()
        else:
            # Try to split "device: message" first
            parts = line.split(':', 1)
            if len(parts) == 2:
                device = parts[0].strip()
                message = parts[1].strip()
            else:
                device = 'Unknown'
                message = line
            X_new = vectorizer.transform([message])
            severity = clf.predict(X_new)[0]
            timestamp = 'Unknown'

        logs.append({
            'timestamp': timestamp,
            'severity': severity,
            'device': device,
            'message': message
        })
    return logs


def count_by_severity(logs):
    counts = {'CRITICAL': 0, 'WARNING': 0, 'INFO': 0}
    for log in logs:
        if log['severity'] in counts:
            counts[log['severity']] += 1
    return counts





# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/sample', methods=['GET'])
def get_sample():
    return jsonify({'logs': SAMPLE_LOGS})


@app.route('/api/parse', methods=['POST'])
def parse():
    global parsed_logs
    data = request.get_json() or {}
    log_text = data.get('logs', '')

    if not log_text:
        return jsonify({'error': 'No logs provided'}), 400

    parsed_logs = parse_logs(log_text)
    return jsonify({
        'success': True,
        'total': len(parsed_logs),
        'classified': True
    })


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Accept a .txt file uploaded from the web UI. The endpoint parses file content and stores parsed_logs in memory."""
    global parsed_logs
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    # only accept .txt
    if not f.filename.lower().endswith('.txt'):
        return jsonify({'error': 'Only .txt files are accepted'}), 400
    try:
        content = f.read().decode('utf-8')
    except Exception:
        # fallback: try reading bytes directly
        content = f.read().decode('latin-1')

    parsed_logs = parse_logs(content)
    return jsonify({'success': True, 'total': len(parsed_logs)})


@app.route('/api/summary', methods=['GET'])
def summary():
    if not parsed_logs:
        return jsonify({'error': 'No logs parsed yet'}), 400

    severity_counts = count_by_severity(parsed_logs)
  

    return jsonify({
        'total': len(parsed_logs),
        'critical': severity_counts['CRITICAL'],
        'warning': severity_counts['WARNING'],
        'info': severity_counts['INFO']
    })


@app.route('/api/chat', methods=['POST'])
def chat():
    if not parsed_logs:
        return jsonify({'message': 'Please load logs first'})

    data = request.get_json() or {}
    user_input = data.get('message', '').lower()

    # --- Show Critical Logs ---
    if 'critical' in user_input:
        crit = [log for log in parsed_logs if log['severity'] == 'CRITICAL']
        return jsonify({
            'type': 'critical',
            'count': len(crit),
            'logs': crit
        })

    # --- Show Warning Logs ---
    elif 'warning' in user_input:
        warn = [log for log in parsed_logs if log['severity'] == 'WARNING']
        return jsonify({
            'type': 'warning',
            'count': len(warn),
            'logs': warn
        })

    # --- Show Info Logs ---
    elif 'info' in user_input:
        info = [log for log in parsed_logs if log['severity'] == 'INFO']
        return jsonify({
            'type': 'info',
            'count': len(info),
            'logs': info
        })

    return jsonify({
        'message': 'Try: "show critical", "show warning", or "show info"'
    })


# Serve static files (optional)
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    print(" ML-powered Network Management Server running at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)





