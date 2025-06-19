from flask import Flask, request, jsonify
import os, requests
from requests.auth import HTTPBasicAuth

app = Flask(__name__)

# Health‑check / home route so GET / and HEAD / return 200
@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "FUB API Middleware is running"}), 200

# 🔑 FUB API Auth using Basic Authentication
FUB_API_KEY = os.getenv("FUB_API_KEY")
FUB_AUTH = HTTPBasicAuth(FUB_API_KEY, "")

# ──────────────── CONTACTS / LEADS ─────────────────

@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    resp = requests.get("https://api.followupboss.com/v1/people", auth=FUB_AUTH)
    return jsonify(resp.json())

@app.route('/get_lead/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}", auth=FUB_AUTH)
    return jsonify(resp.json())

# ──────────────── TASKS ─────────────────

@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    params = {
        "status": request.args.get("status"),
        "assignedTo": request.args.get("assignedTo")
    }
    resp = requests.get("https://api.followupboss.com/v1/tasks", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ──────────────── APPOINTMENTS ─────────────────

@app.route('/get_appointments', methods=['GET'])
def get_appointments():
    params = {
        "start": request.args['start'],
        "end": request.args['end'],
        "agent_id": request.args.get("agent_id"),
        "outcome": request.args.get("outcome")
    }
    resp = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

@app.route('/get_appointments_report', methods=['GET'])
def get_appointments_report():
    params = {"start": request.args['start'], "end": request.args['end']}
    data = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params=params).json()
    report = {}
    for appt in data.get("appointments", []):
        agent = appt.get("assignedAgent", {}).get("id")
        name  = appt.get("assignedAgent", {}).get("name")
        outcome = appt.get("outcome") or "unknown"
        key = (agent, name, outcome)
        report[key] = report.get(key, 0) + 1
    out = []
    for (agent_id, agent_name, outcome), count in report.items():
        out.append({
            "agent": {"id": agent_id, "name": agent_name},
            "outcome": outcome,
            "count": count
        })
    return jsonify({"report": out})

# ──────────────── DEALS ─────────────────

@app.route('/get_deals', methods=['GET'])
def get_deals():
    resp = requests.get("https://api.followupboss.com/v1/deals", auth=FUB_AUTH)
    return jsonify(resp.json())

# ──────────────── LEAD SOURCES ─────────────────

@app.route('/get_lead_sources', methods=['GET'])
def get_lead_sources():
    resp = requests.get("https://api.followupboss.com/v1/people/sources", auth=FUB_AUTH)
    return jsonify(resp.json())

# ──────────────── NOTES ─────────────────

@app.route('/get_notes', methods=['GET'])
def get_notes():
    lead_id = request.args['lead_id']
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}/notes", auth=FUB_AUTH)
    return jsonify(resp.json())

# ──────────────── EVENTS ─────────────────

@app.route('/get_events', methods=['GET'])
def get_events():
    params = {
        "start": request.args.get("start"),
        "end":   request.args.get("end")
    }
    resp = requests.get("https://api.followupboss.com/v1/events", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ──────────────── USERS ─────────────────

@app.route('/get_users', methods=['GET'])
def get_users():
    resp = requests.get("https://api.followupboss.com/v1/users", auth=FUB_AUTH)
    return jsonify(resp.json())

# ──────────────── DEBUG TOKEN ─────────────────

@app.route('/debug_token', methods=['GET'])
def debug_token():
    token = os.getenv("FUB_API_KEY")
    return jsonify({"loaded_token": token[:8] + "...", "length": len(token) if token else 0})

# ──────────────── RUN ─────────────────

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)), debug=True)
