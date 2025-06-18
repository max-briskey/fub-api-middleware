from flask import Flask, request, jsonify
import os, requests

app = Flask(__name__)

# Health‑check / home route so GET / and HEAD / return 200
@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "FUB API Middleware is running"}), 200

# 🔑 YOUR FUB API KEY (in prod, move this into an env var)
FUB_API_KEY = os.getenv("FUB_API_KEY")
HEADERS = {"Authorization": f"Bearer {FUB_API_KEY}"}

# ──────────────── CONTACTS / LEADS ─────────────────

@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    resp = requests.get("https://api.followupboss.com/v1/people", headers=HEADERS)
    return jsonify(resp.json())

@app.route('/get_lead/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}", headers=HEADERS)
    return jsonify(resp.json())

# ──────────────── TASKS ─────────────────

@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    params = {
        "status": request.args.get("status"),
        "assignedTo": request.args.get("assignedTo")
    }
    resp = requests.get("https://api.followupboss.com/v1/tasks", headers=HEADERS, params=params)
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
    resp = requests.get("https://api.followupboss.com/v1/appointments", headers=HEADERS, params=params)
    return jsonify(resp.json())

@app.route('/get_appointments_report', methods=['GET'])
def get_appointments_report():
    params = {"start": request.args['start'], "end": request.args['end']}
    data = requests.get("https://api.followupboss.com/v1/appointments", headers=HEADERS, params=params).json()
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
    resp = requests.get("https://api.followupboss.com/v1/deals", headers=HEADERS)
    return jsonify(resp.json())

# ──────────────── LEAD SOURCES ─────────────────

@app.route('/get_lead_sources', methods=['GET'])
def get_lead_sources():
    resp = requests.get("https://api.followupboss.com/v1/people/sources", headers=HEADERS)
    return jsonify(resp.json())

# ──────────────── NOTES ─────────────────

@app.route('/get_notes', methods=['GET'])
def get_notes():
    lead_id = request.args['lead_id']
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}/notes", headers=HEADERS)
    return jsonify(resp.json())

# ──────────────── EVENTS ─────────────────

@app.route('/get_events', methods=['GET'])
def get_events():
    params = {
        "start": request.args.get("start"),
        "end":   request.args.get("end")
    }
    resp = requests.get("https://api.followupboss.com/v1/events", headers=HEADERS, params=params)
    return jsonify(resp.json())

# ──────────────── USERS ─────────────────

@app.route('/get_users', methods=['GET'])
def get_users():
    resp = requests.get("https://api.followupboss.com/v1/users", headers=HEADERS)
    return jsonify(resp.json())

# ──────────────── RUN ─────────────────

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)), debug=True)

# TEST

@app.route('/debug_token', methods=['GET'])
def debug_token():
    import os
    token = os.getenv("FUB_API_KEY")
    return jsonify({"loaded_token": token})


