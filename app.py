from flask import Flask, request, jsonify, abort, redirect, session, url_for
import os, requests, base64, json, hmac, hashlib
from requests.auth import HTTPBasicAuth

# Google OAuth libraries
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request as GoogleRequest

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET") or "dev-secret"

# ─── Health Check ───────────────────────────────────────────────
@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "FUB API Middleware is running"}), 200

# ─── FUB API Auth ────────────────────────────────────────────────
FUB_API_KEY = os.getenv("FUB_API_KEY")
if not FUB_API_KEY:
    raise RuntimeError("FUB_API_KEY environment variable not set")
FUB_AUTH = HTTPBasicAuth(FUB_API_KEY, "")

# ─── Embedded App Secret ─────────────────────────────────────────
FUB_APP_SECRET = os.getenv("FUB_APP_SECRET")
if not FUB_APP_SECRET:
    raise RuntimeError("FUB_APP_SECRET environment variable not set")

def verify_fub_request(context_b64, signature):
    if not context_b64 or not signature:
        return False
    expected = hmac.new(
        key=FUB_APP_SECRET.encode('utf-8'),
        msg=context_b64.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

@app.route('/embedded', methods=['GET'])
def embedded_app():
    context_b64 = request.args.get("context", "")
    signature   = request.args.get("signature", "")
    if not verify_fub_request(context_b64, signature):
        abort(403, description="Invalid FUB signature")
    padding = '=' * (-len(context_b64) % 4)
    try:
        raw     = base64.urlsafe_b64decode(context_b64 + padding)
        fub_ctx = json.loads(raw)
    except Exception:
        abort(400, description="Malformed FUB context")
    return jsonify({
        "status":    "verified",
        "accountId": fub_ctx.get("account", {}).get("id"),
        "userId":    fub_ctx.get("user", {}).get("id")
    })

# ─── FUB Middleware Endpoints ────────────────────────────────────
@app.route('/get_users', methods=['GET'])
def get_users():
    """
    GET /get_users — returns all users via pagination
    """
    url = "https://api.followupboss.com/v1/users"
    all_users = []
    while url:
        resp = requests.get(url, auth=FUB_AUTH)
        data = resp.json()
        # Append users
        all_users.extend(data.get('users', []))
        # Check for next page
        meta = data.get('_metadata', {})
        url = meta.get('nextLink')
    return jsonify({'users': all_users})

@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    return jsonify(requests.get("https://api.followupboss.com/v1/people", auth=FUB_AUTH).json())

@app.route('/get_lead/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    return jsonify(requests.get(f"https://api.followupboss.com/v1/people/{lead_id}", auth=FUB_AUTH).json())

@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    params = {"status": request.args.get("status"), "assignedTo": request.args.get("assignedTo")}
    return jsonify(requests.get("https://api.followupboss.com/v1/tasks", auth=FUB_AUTH, params=params).json())

@app.route('/get_appointments', methods=['GET'])
def get_appointments():
    start = request.args.get('start'); end = request.args.get('end')
    if not start or not end:
        abort(400, description="Missing required parameters: start and end")
    params = {"start": start, "end": end,
              "agent_id": request.args.get("agent_id"),
              "outcome":  request.args.get("outcome")}
    return jsonify(requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params=params).json())

@app.route('/get_appointments_report', methods=['GET'])
def get_appointments_report():
    start = request.args.get('start'); end = request.args.get('end')
    if not start or not end:
        abort(400, description="Missing required parameters: start and end")
    data = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params={"start": start, "end": end}).json()
    report = {}
    for appt in data.get("appointments", []):
        ag = appt.get("assignedAgent", {})
        key = (ag.get("id"), ag.get("name"), appt.get("outcome") or "unknown")
        report[key] = report.get(key, 0) + 1
    out = [{"agent": {"id": aid, "name": nm}, "outcome": oc, "count": ct} for (aid,nm,oc), ct in report.items()]
    return jsonify({"report": out})

# ─── Calendar Sync via Google OAuth ──────────────────────────────
TOKENS_FILE = 'tokens.json'
def load_tokens():
    try:
        return json.load(open(TOKENS_FILE))
    except:
        return {}
def save_tokens(tokens):
    json.dump(tokens, open(TOKENS_FILE, 'w'))

GOOGLE_CLIENT_CONFIG = json.loads(os.getenv("GOOGLE_OAUTH_CONFIG_JSON", "{}"))
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

@app.route('/auth/google', methods=['GET'])
def auth_google():
    user_id = request.args.get('user_id')
    if not user_id:
        abort(400, "Missing user_id parameter")
    flow = Flow.from_client_config(GOOGLE_CLIENT_CONFIG, SCOPES,
                                   redirect_uri=url_for('oauth2callback', _external=True))
    auth_url, state = flow.authorization_url(prompt='consent', include_granted_scopes=True)
    session['state']   = state
    session['user_id'] = user_id
    return redirect(auth_url)

@app.route('/oauth2callback', methods=['GET'])
def oauth2callback():
    state   = session.get('state'); user_id = session.get('user_id')
    if not state or not user_id:
        abort(400, "Missing OAuth state or user_id in session")
    flow = Flow.from_client_config(GOOGLE_CLIENT_CONFIG, SCOPES,
                                   state=state,
                                   redirect_uri=url_for('oauth2callback', _external=True))
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    tokens = load_tokens()
    tokens[user_id] = {
        'token':         creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri':     creds.token_uri,
        'client_id':     creds.client_id,
        'client_secret': creds.client_secret,
        'scopes':        creds.scopes
    }
    save_tokens(tokens)
    return jsonify({"status": "connected", "user_id": user_id})

@app.route('/get_calendar_events', methods=['GET'])
def get_calendar_events():
    user_id = request.args.get('user_id')
    start   = request.args.get('start')
    end     = request.args.get('end')
    if not (user_id and start and end):
        abort(400, "Require user_id, start, end")
    tokens = load_tokens()
    user_tokens = tokens.get(user_id)
    if not user_tokens:
        abort(404, "User not connected to Google Calendar")
    creds = Credentials(**user_tokens)
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest())
        user_tokens['token'] = creds.token
        save_tokens(tokens)
    service = build('calendar', 'v3', credentials=creds)
    events = service.events().list(
        calendarId='primary', timeMin=start, timeMax=end,
        singleEvents=True, orderBy='startTime'
    ).execute().get('items', [])
    return jsonify({"calendarAppointments": events})

# ─── Aggregated Calendar Appointments ─────────────────────────────
@app.route('/get_all_calendar_events', methods=['GET'])
def get_all_calendar_events():
    start = request.args.get('start'); end = request.args.get('end')
    if not start or not end:
        abort(400, "Missing required parameters: start and end")
    tokens = load_tokens()
    all_events = []
    for user_id, user_tokens in tokens.items():
        creds = Credentials(**user_tokens)
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
            tokens[user_id]['token'] = creds.token
            save_tokens(tokens)
        service = build('calendar', 'v3', credentials=creds)
        events = service.events().list(
            calendarId='primary', timeMin=start, timeMax=end,
            singleEvents=True, orderBy='startTime'
        ).execute().get('items', [])
        for e in events:
            e['fub_user_id'] = user_id
            all_events.append(e)
    return jsonify({"allCalendarAppointments": all_events})

@app.route('/get_deals', methods=['GET'])
def get_deals():
    return jsonify(requests.get("https://api.followupboss.com/v1/deals", auth=FUB_AUTH).json())

@app.route('/get_lead_sources', methods=['GET'])
def get_lead_sources():
    return jsonify(requests.get("https://api.followupboss.com/v1/people/sources", auth=FUB_AUTH).json())

@app.route('/get_notes', methods=['GET'])
def get_notes():
    lead_id = request.args.get('lead_id')
    if not lead_id:
        abort(400, "Missing required parameter: lead_id")
    return jsonify(requests.get(f"https://api.followupboss.com/v1/people/{lead_id}/notes", auth=FUB_AUTH).json())

@app.route('/get_events', methods=['GET'])
def get_events():
    return jsonify(requests.get(
        "https://api.followupboss.com/v1/events",
        auth=FUB_AUTH,
        params={"start": request.args.get('start'), "end": request.args.get('end')}
    ).json())

@app.route('/debug_token', methods=['GET'])
def debug_token():
    return jsonify({"loaded_token": FUB_API_KEY[:8] + '...', "length": len(FUB_API_KEY)})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
