import os
# Allow OAuth 2.0 on HTTPS-terminated load balancers (Render)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask, request, jsonify, abort, redirect, session, url_for
import secrets, requests, base64, json, hmac, hashlib
from requests.auth import HTTPBasicAuth

# Google OAuth libraries
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request as GoogleRequest

# Initialize Flask
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET") or secrets.token_hex(16)
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
        FUB_APP_SECRET.encode('utf-8'),
        context_b64.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

@app.route('/', methods=['GET'])
def health():
    return jsonify({"status": "FUB API Middleware is running"}), 200

@app.route('/embedded', methods=['GET'])
def embedded_app():
    ctx_b64 = request.args.get('context', '')
    sig = request.args.get('signature', '')
    if not verify_fub_request(ctx_b64, sig):
        abort(403, "Invalid FUB signature")
    padding = '=' * (-len(ctx_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(ctx_b64 + padding)
        data = json.loads(raw)
    except Exception:
        abort(400, "Malformed FUB context")
    return jsonify({
        "status": "verified",
        "accountId": data.get('account', {}).get('id'),
        "userId": data.get('user', {}).get('id')
    })

# ─── Helper: FUB GET with pagination ────────────────────────────
def fub_get_paginated(endpoint):
    url = f"https://api.followupboss.com/v1/{endpoint}"
    items = []
    while url:
        resp = requests.get(url, auth=FUB_AUTH)
        resp.raise_for_status()
        obj = resp.json()
        key = 'users' if 'users' in obj else next((k for k,v in obj.items() if isinstance(v, list)), None)
        items.extend(obj.get(key, []))
        url = obj.get('_metadata', {}).get('nextLink')
    return items

@app.route('/get_users', methods=['GET'])
def get_users():
    return jsonify({"users": fub_get_paginated('users')})

@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    resp = requests.get("https://api.followupboss.com/v1/people", auth=FUB_AUTH)
    resp.raise_for_status()
    return jsonify(resp.json())

@app.route('/get_lead/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    resp = requests.get(f"https://api.followupboss.com/v1/people/{lead_id}", auth=FUB_AUTH)
    resp.raise_for_status()
    return jsonify(resp.json())

@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    params = {"status": request.args.get('status'), "assignedTo": request.args.get('assignedTo')}
    resp = requests.get("https://api.followupboss.com/v1/tasks", auth=FUB_AUTH, params=params)
    resp.raise_for_status()
    return jsonify(resp.json())

@app.route('/get_appointments', methods=['GET'])
def get_appointments():
    start = request.args.get('start'); end = request.args.get('end')
    if not start or not end:
        abort(400, "Missing required parameters: start and end")
    params = {"start": start, "end": end, "agent_id": request.args.get('agent_id'), "outcome": request.args.get('outcome')}
    resp = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params=params)
    resp.raise_for_status()
    return jsonify(resp.json())

@app.route('/get_appointments_report', methods=['GET'])
def get_appointments_report():
    start = request.args.get('start'); end = request.args.get('end')
    if not start or not end:
        abort(400, "Missing required parameters: start and end")
    resp = requests.get("https://api.followupboss.com/v1/appointments", auth=FUB_AUTH, params={"start": start, "end": end})
    resp.raise_for_status()
    appts = resp.json().get('appointments', [])
    report = {}
    for a in appts:
        ag = a.get('assignedAgent', {})
        key = (ag.get('id'), ag.get('name'), a.get('outcome') or 'unknown')
        report[key] = report.get(key, 0) + 1
    result = [{"agent": {"id": aid, "name": nm}, "outcome": oc, "count": ct} for (aid,nm,oc), ct in report.items()]
    return jsonify({"report": result})

# ─── Google OAuth Calendar Integration ───────────────────────────
REDIRECT_URI = os.getenv('OAUTH_REDIRECT_URI')
if not REDIRECT_URI:
    raise RuntimeError("OAUTH_REDIRECT_URI not set")
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']
SECRETS_FILE = os.getenv('GOOGLE_CLIENT_SECRETS_FILE', 'credentials.json')
TOKENS_FILE = 'tokens.json'

def load_tokens():
    if os.path.exists(TOKENS_FILE):
        return json.load(open(TOKENS_FILE))
    return {}

def save_tokens(tokens):
    json.dump(tokens, open(TOKENS_FILE, 'w'))

@app.route('/auth/google', methods=['GET'])
def auth_google():
    try:
        user_id = request.args.get('user_id') or abort(400, 'Missing user_id')
        flow = Flow.from_client_secrets_file(SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
        auth_url, state = flow.authorization_url(prompt='consent')
        session['state'] = state
        session['user_id'] = user_id
        return redirect(auth_url)
    except Exception as e:
        return jsonify({'error': 'auth_google_failed', 'message': str(e)}), 500

@app.route('/oauth2callback', methods=['GET'])
def oauth2callback():
    try:
        state = session.get('state'); user_id = session.get('user_id')
        if not state or not user_id:
            abort(400, 'OAuth session error')
        flow = Flow.from_client_secrets_file(SECRETS_FILE, scopes=SCOPES, state=state, redirect_uri=REDIRECT_URI)
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
        return jsonify({'status': 'connected', 'user_id': user_id})
    except Exception as e:
        import traceback
        return jsonify({'error': 'oauth2callback_failed', 'message': str(e), 'trace': traceback.format_exc()}), 500

@app.route('/get_calendar_events', methods=['GET'])
def get_calendar_events():
    user_id = request.args.get('user_id'); start = request.args.get('start'); end = request.args.get('end')
    if not (user_id and start and end):
        abort(400, 'Require user_id, start, end')
    tokens = load_tokens().get(user_id) or abort(404, 'Not connected')
    creds = Credentials(**tokens)
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest()); tokens['token'] = creds.token; save_tokens(tokens)
    service = build('calendar', 'v3', credentials=creds)
    items = service.events().list(calendarId='primary', timeMin=start, timeMax=end, singleEvents=True, orderBy='startTime').execute().get('items', [])
    return jsonify({'calendarAppointments': items})

@app.route('/get_all_calendar_events', methods=['GET'])
def get_all_calendar_events():
    start = request.args.get('start'); end = request.args.get('end') or abort(400, 'Missing start/end')
    tokens_map = load_tokens(); all_events = []
    for uid, tok in tokens_map.items():
        creds = Credentials(**tok)
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest()); tok['token'] = creds.token; save_tokens(tokens_map)
        service = build('calendar', 'v3', credentials=creds)
        events = service.events().list(calendarId='primary', timeMin=start, timeMax=end, singleEvents=True, orderBy='startTime').execute().get('items', [])
        for e in events:
            e['fub_user_id'] = uid
            all_events.append(e)
    return jsonify({'allCalendarAppointments': all_events})

# ─── Debug & Other Endpoints ────────────────────────────────────
@app.route('/debug_token', methods=['GET'])
def debug_token():
    return jsonify({'loaded_token': FUB_API_KEY[:8] + '...', 'length': len(FUB_API_KEY)})

@app.route('/debug_oauth', methods=['GET'])
def debug_oauth():
    return jsonify({
        'OAUTH_REDIRECT_URI': REDIRECT_URI,
        'GOOGLE_CLIENT_SECRETS_FILE': SECRETS_FILE,
        'ENV_VARS': {
            'FUB_API_KEY': bool(os.getenv('FUB_API_KEY')),
            'FUB_APP_SECRET': bool(os.getenv('FUB_APP_SECRET')),
            'FLASK_SECRET': bool(os.getenv('FLASK_SECRET'))
        }
    })

@app.route('/dump_credentials', methods=['GET'])
def dump_credentials():
    try:
        return jsonify({'credentials': json.load(open(SECRETS_FILE))})
    except Exception as e:
        return jsonify({'error': 'dump_failed', 'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
