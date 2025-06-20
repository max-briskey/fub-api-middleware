from flask import Flask, request, jsonify, abort, redirect, session, url_for
import os, requests, base64, json, hmac, hashlib
from requests.auth import HTTPBasicAuth

# Google OAuth libraries
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request as GoogleRequest

# Initialize Flask
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET")  # Set this in Render env vars
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET not set")
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# ─── FUB API Authentication ─────────────────────────────────────
FUB_API_KEY = os.getenv("FUB_API_KEY")
if not FUB_API_KEY:
    raise RuntimeError("FUB_API_KEY not set")
FUB_AUTH = HTTPBasicAuth(FUB_API_KEY, "")

# ─── Embedded App Secret ───────────────────────────────────────
FUB_APP_SECRET = os.getenv("FUB_APP_SECRET")
if not FUB_APP_SECRET:
    raise RuntimeError("FUB_APP_SECRET not set")

def verify_fub_request(context_b64, signature):
    expected = hmac.new(
        key=FUB_APP_SECRET.encode('utf-8'),
        msg=context_b64.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

@app.route('/', methods=['GET'])
def health():
    return jsonify({"status": "FUB API Middleware is running"}), 200

@app.route('/embedded', methods=['GET'])
def embedded_app():
    context_b64 = request.args.get('context', '')
    signature   = request.args.get('signature', '')
    if not verify_fub_request(context_b64, signature):
        abort(403, "Invalid FUB signature")
    # Decode context
    padding = '=' * (-len(context_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(context_b64 + padding)
        ctx = json.loads(raw)
    except Exception:
        abort(400, "Malformed FUB context")
    return jsonify({
        "status": "verified",
        "accountId": ctx.get('account', {}).get('id'),
        "userId":    ctx.get('user', {}).get('id')
    })

# ─── Helper: FUB GET with pagination ────────────────────────────
def fub_get_paginated(path):
    url = f"https://api.followupboss.com/v1/{path}"
    items = []
    while url:
        r = requests.get(url, auth=FUB_AUTH)
        r.raise_for_status()
        data = r.json()
        # path 'users' returns 'users', others return top-level arrays
        key = 'users' if 'users' in data else next((k for k in data if isinstance(data[k], list)), None)
        items.extend(data.get(key, []))
        url = data.get('_metadata', {}).get('nextLink')
    return items

@app.route('/get_users', methods=['GET'])
def get_users():
    users = fub_get_paginated('users')
    return jsonify({"users": users})

# ─── FUB Middleware Endpoints ───────────────────────────────────
@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    r = requests.get("https://api.followupboss.com/v1/people", auth=FUB_AUTH)
    r.raise_for_status()
    return jsonify(r.json())

@app.route('/get_lead/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    r = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}", auth=FUB_AUTH)
    r.raise_for_status()
    return jsonify(r.json())

@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    params = {"status": request.args.get('status'), "assignedTo": request.args.get('assignedTo')}
    r = requests.get("https://api.followupboss.com/v1/tasks", auth=FUB_AUTH, params=params)
    r.raise_for_status()
    return jsonify(r.json())

@app.route('/get_appointments', methods=['GET'])
def get_appointments():
    start = request.args.get('start'); end = request.args.get('end')
    if not start or not end:
        abort(400, "Missing required parameters: start and end")
    params = {"start": start, "end": end, "agent_id": request.args.get('agent_id'), "outcome": request.args.get('outcome')}
    r = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params=params)
    r.raise_for_status()
    return jsonify(r.json())

@app.route('/get_appointments_report', methods=['GET'])
def get_appointments_report():
    start = request.args.get('start'); end = request.args.get('end')
    if not start or not end:
        abort(400, "Missing required parameters: start and end")
    r = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params={"start": start, "end": end})
    r.raise_for_status()
    data = r.json().get('appointments', [])
    report = {}
    for appt in data:
        ag = appt.get('assignedAgent', {})
        key = (ag.get('id'), ag.get('name'), appt.get('outcome') or 'unknown')
        report[key] = report.get(key, 0) + 1
    out = [{"agent": {"id": aid, "name": nm}, "outcome": oc, "count": ct} for (aid,nm,oc), ct in report.items()]
    return jsonify({"report": out})

# ─── Google OAuth Calendar Integration ───────────────────────────
TOKENS_FILE = 'tokens.json'
def load_tokens():
    if os.path.exists(TOKENS_FILE): return json.load(open(TOKENS_FILE))
    return {}
def save_tokens(tokens):
    json.dump(tokens, open(TOKENS_FILE, 'w'))

SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']
SECRETS_FILE = os.getenv('GOOGLE_CLIENT_SECRETS_FILE', 'credentials.json')

@app.route('/auth/google', methods=['GET'])
def auth_google():
    user_id = request.args.get('user_id') or abort(400, 'Missing user_id')
    flow = Flow.from_client_secrets_file(
        SECRETS_FILE, scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    auth_url, state = flow.authorization_url(prompt='consent', include_granted_scopes=True)
    session['state'] = state
    session['user_id'] = user_id
    return redirect(auth_url)

@app.route('/oauth2callback', methods=['GET'])
def oauth2callback():
    state = session.get('state'); user_id = session.get('user_id')
    if not state or not user_id: abort(400, 'OAuth session error')
    flow = Flow.from_client_secrets_file(
        SECRETS_FILE, scopes=SCOPES,
        state=state, redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    tokens = load_tokens()
    tokens[user_id] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    save_tokens(tokens)
    return jsonify({'status':'connected','user_id':user_id})

@app.route('/get_calendar_events', methods=['GET'])
def get_calendar_events():
    user_id = request.args.get('user_id'); start = request.args.get('start'); end = request.args.get('end')
    if not (user_id and start and end): abort(400, 'Require user_id, start, end')
    tokens = load_tokens().get(user_id) or abort(404,'Not connected')
    creds = Credentials(**tokens)
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest()); tokens['token']=creds.token; save_tokens({user_id:tokens})
    service = build('calendar','v3',credentials=creds)
    events = service.events().list(calendarId='primary', timeMin=start, timeMax=end, singleEvents=True, orderBy='startTime').execute().get('items', [])
    return jsonify({'calendarAppointments': events})

@app.route('/get_all_calendar_events', methods=['GET'])
def get_all_calendar_events():
    start = request.args.get('start'); end = request.args.get('end') or abort(400,'Missing start/end')
    all_tokens = load_tokens(); all_events=[]
    for uid, tok in all_tokens.items():
        creds = Credentials(**tok)
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest()); tok['token']=creds.token; save_tokens(all_tokens)
        service = build('calendar','v3',credentials=creds)
        items = service.events().list(calendarId='primary', timeMin=start, timeMax=end, singleEvents=True, orderBy='startTime').execute().get('items', [])
        for e in items: e['fub_user_id']=uid; all_events.append(e)
    return jsonify({'allCalendarAppointments': all_events})

# ─── Remaining FUB Endpoints ─────────────────────────────────────
@app.route('/get_deals', methods=['GET'])
def get_deals():
    r = requests.get("https://api.followupboss.com/v1/deals", auth=FUB_AUTH); r.raise_for_status(); return jsonify(r.json())

@app.route('/get_lead_sources', methods=['GET'])
def get_lead_sources():
    r = requests.get("https://api.followupboss.com/v1/people/sources", auth=FUB_AUTH); r.raise_for_status(); return jsonify(r.json())

@app.route('/get_notes', methods=['GET'])
def get_notes():
    lead_id = request.args.get('lead_id') or abort(400,'Missing lead_id')
    r = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}/notes", auth=FUB_AUTH)
    r.raise_for_status(); return jsonify(r.json())

@app.route('/get_events', methods=['GET'])
def get_events():
    r = requests.get("https://api.followupboss.com/v1/events", auth=FUB_AUTH, params={'start':request.args.get('start'),'end':request.args.get('end')}); r.raise_for_status(); return jsonify(r.json())

@app.route('/debug_token', methods=['GET'])
def debug_token():
    return jsonify({'loaded_token':FUB_API_KEY[:8]+'...', 'length':len(FUB_API_KEY)})

if __name__ == '__main__':
    port = int(os.getenv('PORT',10000)); app.run(host='0.0.0.0', port=port)
