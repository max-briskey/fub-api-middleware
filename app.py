from flask import Flask, request, jsonify, abort
import os, requests, base64, json, hmac, hashlib
from requests.auth import HTTPBasicAuth

app = Flask(__name__)

# ─── Home / Health Check ────────────────────────────────────────
@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "FUB API Middleware is running"}), 200

# 🔑 FUB API Authentication (Basic Auth)
FUB_API_KEY = os.getenv("FUB_API_KEY")
if not FUB_API_KEY:
    raise RuntimeError("FUB_API_KEY environment variable not set")
FUB_AUTH = HTTPBasicAuth(FUB_API_KEY, "")

# 🔐 Embedded App Secret for verifying FUB iframe requests
FUB_APP_SECRET = os.getenv("FUB_APP_SECRET")
if not FUB_APP_SECRET:
    raise RuntimeError("FUB_APP_SECRET environment variable not set")

def verify_fub_request(context_b64, signature):
    """
    Verify HMAC-SHA256 signature for FUB embedded context.
    """
    if not context_b64 or not signature:
        return False
    expected = hmac.new(
        key=FUB_APP_SECRET.encode('utf-8'),
        msg=context_b64.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# ─── Embedded App Route ─────────────────────────────────────────
@app.route('/embedded', methods=['GET'])
def embedded_app():
    """
    GET /embedded?context=<base64>&signature=<hmac>
    Verifies and decodes FUB context, returning accountId and userId.
    """
    context_b64 = request.args.get("context", "")
    signature   = request.args.get("signature", "")
    if not verify_fub_request(context_b64, signature):
        abort(403, description="Invalid FUB signature")
    # Decode base64 context
    padding = '=' * (-len(context_b64) % 4)
    try:
        raw      = base64.urlsafe_b64decode(context_b64 + padding)
        fub_ctx  = json.loads(raw)
    except Exception:
        abort(400, description="Malformed FUB context")
    account_id = fub_ctx.get("account", {}).get("id")
    user_id    = fub_ctx.get("user", {}).get("id")
    return jsonify({"status": "verified", "accountId": account_id, "userId": user_id})

# ─── GET USERS ─────────────────────────────────────────────────────
@app.route('/get_users', methods=['GET'])
def get_users():
    resp = requests.get("https://api.followupboss.com/v1/users", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET CONTACTS ─────────────────────────────────────────────────
@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    resp = requests.get("https://api.followupboss.com/v1/people", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET LEAD DETAILS ───────────────────────────────────────────────
@app.route('/get_lead/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET TASKS ─────────────────────────────────────────────────────
@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    params = {
        "status":     request.args.get("status"),
        "assignedTo": request.args.get("assignedTo")
    }
    resp = requests.get("https://api.followupboss.com/v1/tasks", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ─── GET APPOINTMENTS ───────────────────────────────────────────────
@app.route('/get_appointments', methods=['GET'])
def get_appointments():
    start = request.args.get('start')
    end   = request.args.get('end')
    if not start or not end:
        abort(400, description="Missing required parameters: start and end")
    params = {"start": start, "end": end,
              "agent_id": request.args.get("agent_id"),
              "outcome":  request.args.get("outcome")}
    resp = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ─── GET APPOINTMENTS REPORT ────────────────────────────────────────
@app.route('/get_appointments_report', methods=['GET'])
def get_appointments_report():
    start = request.args.get('start')
    end   = request.args.get('end')
    if not start or not end:
        abort(400, description="Missing required parameters: start and end")
    data = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH,
                        params={"start": start, "end": end}).json()
    report = {}
    for appt in data.get("appointments", []):
        ag = appt.get("assignedAgent", {})
        agent_id   = ag.get("id")
        agent_name = ag.get("name")
        outcome    = appt.get("outcome") or "unknown"
        key = (agent_id, agent_name, outcome)
        report[key] = report.get(key, 0) + 1
    out = [{"agent": {"id": aid, "name": nm}, "outcome": oc, "count": ct}
           for (aid, nm, oc), ct in report.items()]
    return jsonify({"report": out})

# ─── GET CALENDAR APPOINTMENTS ─────────────────────────────────────
@app.route('/get_calendar_appointments', methods=['GET'])
def get_calendar_appointments():
    start = request.args.get('start')
    end   = request.args.get('end')
    if not start or not end:
        abort(400, description="Missing required parameters: start and end")
    # Fetch events feed\  
    resp = requests.get("https://api.followupboss.com/v1/events", auth=FUB_AUTH,
                        params={"start": start, "end": end, "limit": 1000})
    events = resp.json().get('events', [])
    # Filter calendar events
    cal_events = []
    for e in events:
        if e.get('type') == 'Appointment' or e.get('system') in ('Google', 'Outlook'):
            cal_events.append({
                "id":         e.get('id'),
                "occurred":   e.get('occurred'),
                "type":       e.get('type'),
                "description":e.get('description'),
                "personId":   e.get('personId'),
                "system":     e.get('system')
            })
    return jsonify({"calendarAppointments": cal_events})

# ─── GET DEALS ─────────────────────────────────────────────────────
@app.route('/get_deals', methods=['GET'])
def get_deals():
    resp = requests.get("https://api.followupboss.com/v1/deals", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET LEAD SOURCES ───────────────────────────────────────────────
@app.route('/get_lead_sources', methods=['GET'])
def get_lead_sources():
    resp = requests.get("https://api.followupboss.com/v1/people/sources", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET NOTES ─────────────────────────────────────────────────────
@app.route('/get_notes', methods=['GET'])
def get_notes():
    lead_id = request.args.get('lead_id')
    if not lead_id:
        abort(400, description="Missing required parameter: lead_id")
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}/notes", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET EVENTS ────────────────────────────────────────────────────
@app.route('/get_events', methods=['GET'])
def get_events():
    params = {"start": request.args.get('start'), "end": request.args.get('end')}
    resp = requests.get("https://api.followupboss.com/v1/events", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ─── DEBUG TOKEN ───────────────────────────────────────────────────
@app.route('/debug_token', methods=['GET'])
def debug_token():
    token = FUB_API_KEY
    return jsonify({"loaded_token": f"{token[:8]}...", "length": len(token)})

# ─── RUN SERVER ───────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
