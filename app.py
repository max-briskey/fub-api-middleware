from flask import Flask, request, jsonify, abort
import os, requests, base64, json, hmac, hashlib
from requests.auth import HTTPBasicAuth

app = Flask(__name__)

# ─── Home / Health Check ────────────────────
@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "FUB API Middleware is running"}), 200

# 🔑 FUB API Auth using Basic Authentication
FUB_API_KEY = os.getenv("FUB_API_KEY")
FUB_AUTH    = HTTPBasicAuth(FUB_API_KEY, "")

# 🔐 Embedded App Secret for verifying FUB iframe requests
FUB_APP_SECRET = os.getenv("FUB_APP_SECRET")

def verify_fub_request(context_b64, signature):
    """
    Verify the HMAC-SHA256 signature of the base64-encoded context from FUB.
    Returns True if valid, False otherwise.
    """
    if not context_b64 or not signature or not FUB_APP_SECRET:
        return False
    expected_sig = hmac.new(
        key=FUB_APP_SECRET.encode('utf-8'),
        msg=context_b64.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_sig, signature)

# ─── Embedded App Route (FUB Context Verifier) ─────────────────
@app.route('/embedded', methods=['GET'])
def embedded_app():
    context_b64 = request.args.get("context", "")
    signature   = request.args.get("signature", "")

    # 1) Verify request origin
    if not verify_fub_request(context_b64, signature):
        abort(403, description="Invalid FUB signature")

    # 2) Decode base64 context JSON
    try:
        padding     = '=' * (-len(context_b64) % 4)
        decoded     = base64.urlsafe_b64decode(context_b64 + padding)
        fub_context = json.loads(decoded)
    except Exception:
        abort(400, description="Malformed FUB context")

    # 3) Extract FUB-provided context
    account_id = fub_context.get("account", {}).get("id")
    user_id    = fub_context.get("user", {}).get("id")

    # 4) Return context or render your frontend here
    return jsonify({
        "status":    "verified",
        "accountId": account_id,
        "userId":    user_id
    })

# ─── CONTACTS / LEADS ───────────────────────────────────────────
@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    resp = requests.get("https://api.followupboss.com/v1/people", auth=FUB_AUTH)
    return jsonify(resp.json())

@app.route('/get_lead/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── TASKS ───────────────────────────────────────────────────────
@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    params = {
        "status":     request.args.get("status"),
        "assignedTo": request.args.get("assignedTo")
    }
    resp = requests.get("https://api.followupboss.com/v1/tasks", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ─── APPOINTMENTS ─────────────────────────────────────────────────
@app.route('/get_appointments', methods=['GET'])
def get_appointments():
    start = request.args.get('start')
    end   = request.args.get('end')
    if not start or not end:
        abort(400, description="Missing required parameters: start and end")
    params = {
        "start":    start,
        "end":      end,
        "agent_id": request.args.get("agent_id"),
        "outcome":  request.args.get("outcome")
    }
    resp = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

@app.route('/get_appointments_report', methods=['GET'])
def get_appointments_report():
    start = request.args.get('start')
    end   = request.args.get('end')
    if not start or not end:
        abort(400, description="Missing required parameters: start and end")
    params = {"start": start, "end": end}
    data   = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params=params).json()
    report = {}
    for appt in data.get("appointments", []):
        agent   = appt.get("assignedAgent", {}).get("id")
        name    = appt.get("assignedAgent", {}).get("name")
        outcome = appt.get("outcome") or "unknown"
        key     = (agent, name, outcome)
        report[key] = report.get(key, 0) + 1
    out = [{"agent": {"id": ag, "name": nm}, "outcome": oc, "count": ct} 
           for (ag, nm, oc), ct in report.items()]
    return jsonify({"report": out})

# ─── DEALS ───────────────────────────────────────────────────────
@app.route('/get_deals', methods=['GET'])
def get_deals():
    resp = requests.get("https://api.followupboss.com/v1/deals", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── LEAD SOURCES ─────────────────────────────────────────────────
@app.route('/get_lead_sources', methods=['GET'])
def get_lead_sources():
    resp = requests.get("https://api.followupboss.com/v1/people/sources", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── NOTES ───────────────────────────────────────────────────────
@app.route('/get_notes', methods=['GET'])
def get_notes():
    lead_id = request.args.get('lead_id')
    if not lead_id:
        abort(400, description="Missing required parameter: lead_id")
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}/notes", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── EVENTS ─────────────────────────────────────────────────────
@app.route('/get_events', methods=['GET'])
def get_events():
    params = {
        "start": request.args.get("start"),
        "end":   request.args.get("end")
    }
    resp = requests.get("https://api.followupboss.com/v1/events", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ─── USERS ──────────────────────────────────────────────────────
@app.route('/get_users', methods=['GET'])
def get_users():
    resp = requests.get("https://api.followupboss.com/v1/users", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── DEBUG TOKEN ─────────────────────────────────────────────────
@app.route('/debug_token', methods=['GET'])
def debug_token():
    token = os.getenv("FUB_API_KEY", "")
    return jsonify({"loaded_token": f"{token[:8]}...", "length": len(token)})

# ─── RUN SERVER ─────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
