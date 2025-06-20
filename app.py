from flask import Flask, request, jsonify, abort
import os, requests, base64, json, hmac, hashlib
from requests.auth import HTTPBasicAuth

app = Flask(__name__)

# ─── Home / Health Check ────────────────────
@app.route('/', methods=['GET'])
def home():
    """
    GET /
    Response:
      200 OK
      {
        "status": "FUB API Middleware is running"
      }
    """
    return jsonify({"status": "FUB API Middleware is running"}), 200

# 🔑 FUB API Auth using Basic Authentication
token = os.getenv("FUB_API_KEY")
FUB_AUTH = HTTPBasicAuth(token, "")

# 🔐 Embedded App Secret for verifying FUB iframe requests
FUB_APP_SECRET = os.getenv("FUB_APP_SECRET")

def verify_fub_request(context_b64, signature):
    """
    Verify HMAC-SHA256 signature for FUB embedded context.
    Returns True if valid.
    """
    if not context_b64 or not signature or not FUB_APP_SECRET:
        return False
    expected = hmac.new(
        key=FUB_APP_SECRET.encode(),
        msg=context_b64.encode(),
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# ─── Embedded App Route ────────────────────────────────────────
@app.route('/embedded', methods=['GET'])
def embedded_app():
    """
    GET /embedded?context=<base64>&signature=<hmac>
    Verifies and decodes FUB context, returning:
      {
        "status": "verified",
        "accountId": <int>,
        "userId": <int>
      }
    """
    context_b64 = request.args.get("context", "")
    signature   = request.args.get("signature", "")
    if not verify_fub_request(context_b64, signature):
        abort(403, description="Invalid FUB signature")
    # fix padding and decode
    padding = '=' * (-len(context_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(context_b64 + padding)
        fub_ctx = json.loads(raw)
    except Exception:
        abort(400, description="Malformed FUB context")
    account_id = fub_ctx.get("account", {}).get("id")
    user_id    = fub_ctx.get("user", {}).get("id")
    return jsonify({"status": "verified", "accountId": account_id, "userId": user_id})

# ─── GET USERS ─────────────────────────────────────────────────
@app.route('/get_users', methods=['GET'])
def get_users():
    """
    GET /get_users
    Response:
      {
        "users": [
          {
            "id": int,
            "name": str,
            "role": str,
            "isOwner": bool
          }, ...
        ]
      }
    """
    resp = requests.get("https://api.followupboss.com/v1/users", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET CONTACTS ──────────────────────────────────────────────
@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    """
    GET /get_contacts
    Response:
      {
        "people": [
          {
            "id": int,
            "firstName": str,
            "lastName": str,
            "email": str,
            "stage": str,
            "assignedAgent": {"id": int, "name": str}
          }, ...
        ]
      }
    """
    resp = requests.get("https://api.followupboss.com/v1/people", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET LEAD DETAILS ───────────────────────────────────────────
@app.route('/get_lead/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    """
    GET /get_lead/<lead_id>
    Path params:
      lead_id: string
    Response:
      person object (same schema as above)
    """
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET TASKS ─────────────────────────────────────────────────
@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    """
    GET /get_tasks?status=&assignedTo=
    Query params:
      status: "all"|"completed"|"incomplete"
      assignedTo: user ID string
    Response:
      {
        "tasks": [
          {"id": int, "title": str, "dueDate": str, "status": str,
           "assignedTo": {"id": int, "name": str}}, ...]
      }
    """
    params = {"status": request.args.get("status"), "assignedTo": request.args.get("assignedTo")}
    resp = requests.get("https://api.followupboss.com/v1/tasks", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ─── GET APPOINTMENTS ────────────────────────────────────────────
@app.route('/get_appointments', methods=['GET'])
def get_appointments():
    """
    GET /get_appointments?start=<YYYY-MM-DD>&end=<YYYY-MM-DD>&agent_id=&outcome=
    Query params:
      start: required date
      end: required date
      agent_id: optional
      outcome: optional
    Response:
      {
        "appointments": [
          {"id": int, "date": str, "outcome": str, "type": str,
           "contact": {"id": int, "name": str},
           "assignedAgent": {"id": int, "name": str}}, ...]
      }
    """
    start = request.args.get('start')
    end   = request.args.get('end')
    if not start or not end:
        abort(400, description="Missing required parameters: start and end")
    params = {"start": start, "end": end, "agent_id": request.args.get("agent_id"), "outcome": request.args.get("outcome")}
    resp = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ─── GET APPOINTMENTS REPORT ─────────────────────────────────────
@app.route('/get_appointments_report', methods=['GET'])
def get_appointments_report():
    """
    GET /get_appointments_report?start=&end=
    Aggregated counts by agent and outcome:
      {"report": [{"agent": {"id": int, "name": str}, "outcome": str, "count": int}, ...]}
    """
    start = request.args.get('start')
    end   = request.args.get('end')
    if not start or not end:
        abort(400, description="Missing required parameters: start and end")
    data = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params={"start": start, "end": end}).json()
    report = {}
    for appt in data.get("appointments", []):
        agent = appt.get("assignedAgent", {}).get("id")
        name  = appt.get("assignedAgent", {}).get("name")
        outcome = appt.get("outcome") or "unknown"
        key = (agent, name, outcome)
        report[key] = report.get(key, 0) + 1
    out = [{"agent": {"id": ag, "name": nm}, "outcome": oc, "count": ct} for (ag, nm, oc), ct in report.items()]
    return jsonify({"report": out})

# ─── GET DEALS ──────────────────────────────────────────────────
@app.route('/get_deals', methods=['GET'])
def get_deals():
    """
    GET /get_deals
    Response:
      {"deals": [{"id": int, "stage": str, "price": float, "agent": {"id": int, "name": str}}, ...]}
    """
    resp = requests.get("https://api.followupboss.com/v1/deals", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET LEAD SOURCES ─────────────────────────────────────────────
@app.route('/get_lead_sources', methods=['GET'])
def get_lead_sources():
    """
    GET /get_lead_sources
    Response:
      {"sources": [{"source": str, "count": int}, ...]}
    """
    resp = requests.get("https://api.followupboss.com/v1/people/sources", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET NOTES ──────────────────────────────────────────────────
@app.route('/get_notes', methods=['GET'])
def get_notes():
    """
    GET /get_notes?lead_id=<id>
    Response:
      {"notes": [{"id": int, "body": str, "createdBy": {"id": int, "name": str}, "dateCreated": str}, ...]}
    """
    lead_id = request.args.get('lead_id')
    if not lead_id:
        abort(400, description="Missing required parameter: lead_id")
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}/notes", auth=FUB_AUTH)
    return jsonify(resp.json())

# ─── GET EVENTS ─────────────────────────────────────────────────
@app.route('/get_events', methods=['GET'])
def get_events():
    """
    GET /get_events?start=&end=
    Response: FUB native event list JSON
    """
    params = {"start": request.args.get("start"), "end": request.args.get("end")}
    resp = requests.get("https://api.followupboss.com/v1/events", auth=FUB_AUTH, params=params)
    return jsonify(resp.json())

# ─── DEBUG TOKEN ─────────────────────────────────────────────────
@app.route('/debug_token', methods=['GET'])
def debug_token():
    """GET /debug_token returns loaded key length and snippet"""
    token = os.getenv("FUB_API_KEY", "")
    return jsonify({"loaded_token": f"{token[:8]}...", "length": len(token)})

# ─── RUN SERVER ─────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
