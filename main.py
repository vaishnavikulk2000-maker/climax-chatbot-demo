# main.py
#
# Google Cloud Function (Gen 2, Python 3.11)
# Entry point: get_secure_file_url
#
import os
import json
from datetime import timedelta
import requests
from google.cloud import storage
from flask import Request

def _cors_headers(allow_origin):
    """Construct minimal CORS headers used for all responses."""
    return {
        "Access-Control-Allow-Origin": allow_origin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Vary": "Origin",
    }

def get_secure_file_url(request: Request):
    """
    Cloud Function entry point.
    """
    # Handle CORS preflight first with wildcard to eliminate browser blocks
    if request.method == "OPTIONS":
        headers = _cors_headers("*")
        headers["Access-Control-Max-Age"] = "3600"
        return ("", 204, headers)

    # Only accept POST for endpoint operation
    if request.method != "POST":
        return (json.dumps({"error": "Method not allowed"}), 405, _cors_headers("*"))

    # Parse JSON body
    try:
        payload = request.get_json(silent=True)
    except Exception:
        payload = None

    if not payload or not isinstance(payload, dict):
        return (json.dumps({"error": "Invalid JSON payload"}), 400, _cors_headers("*"))

    filename = payload.get("filename")
    recaptcha_token = payload.get("recaptcha_token")

    if not filename or not recaptcha_token:
        return (json.dumps({"error": "Missing 'filename' or 'recaptcha_token'"}), 400, _cors_headers("*"))

    # Server-side reCAPTCHA verification
    RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET_KEY")
    if not RECAPTCHA_SECRET:
        return (json.dumps({"error": "Server misconfiguration"}), 500, _cors_headers("*"))

    try:
        r = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET, "response": recaptcha_token},
            timeout=5,
        )
    except requests.RequestException:
        return (json.dumps({"error": "reCAPTCHA verification request failed"}), 503, _cors_headers("*"))

    if r.status_code != 200:
        return (json.dumps({"error": "reCAPTCHA verification failed"}), 403, _cors_headers("*"))

    verification = r.json()
    if not verification.get("success", False):
        return (json.dumps({"error": "reCAPTCHA not successful"}), 403, _cors_headers("*"))

    score = float(verification.get("score", 0.0))
    if score < 0.5:
        return (json.dumps({"error": "reCAPTCHA score too low"}), 403, _cors_headers("*"))

    # Check the file exists in the private GCS bucket
    BUCKET_NAME = os.environ.get("BUCKET_NAME")
    if not BUCKET_NAME:
        return (json.dumps({"error": "Server misconfiguration: BUCKET_NAME missing"}), 500, _cors_headers("*"))

    try:
        client = storage.Client()
        bucket = client.bucket(BUCKET_NAME)
        blob = bucket.blob(filename)
        if not blob.exists(client):
            return (json.dumps({"error": "File not found"}), 404, _cors_headers("*"))
    except Exception as e:
        return (json.dumps({"error": "Error checking file existence"}), 500, _cors_headers("*"))

    # Generate a v4 signed URL with strict 5-minute TTL
    try:
        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=5),
            method="GET",
        )
    except Exception as e:
        return (json.dumps({"error": "Failed to generate signed URL"}), 500, _cors_headers("*"))

    # Success: return signed URL as JSON with CORS headers
    response_body = json.dumps({"signed_url": signed_url})
    headers = _cors_headers("*")
    headers["Content-Type"] = "application/json"
    return (response_body, 200, headers)