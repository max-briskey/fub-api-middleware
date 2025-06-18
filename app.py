from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

FUB_API_KEY = os.environ.get("FUB_API_KEY")
HEADERS = {"Authorization": f"Bearer {FUB_API_KEY}"}

@app.route('/')
def home():
    return {"status": "FUB API Middleware is running."}

@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    url = "https://api.followupboss.com/v1/people"
    response = requests.get(url, headers=HEADERS)
    return jsonify(response.json())

@app.route('/get_lead/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    url = f"https://api.followupboss.com/v1/people/{lead_id}"
    response = requests.get(url, headers=HEADERS)
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
