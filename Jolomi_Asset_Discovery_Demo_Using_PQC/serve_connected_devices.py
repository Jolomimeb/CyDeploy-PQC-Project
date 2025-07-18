from flask import Flask, jsonify
import json

app = Flask(__name__)

@app.route("/devices")
def devices():
    with open("connected_devices.json") as f:
        return jsonify(json.load(f))

app.run(host="0.0.0.0", port=8000)