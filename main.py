# main.py
#
# Google Cloud Function (Gen 2, Python 3.11)
# Entry point: get_secure_file_url
#
# Security summary (server-side):
# - Accepts only POST requests from the single allowed origin (strict CORS).
# - Verifies reCAPTCHA v3 token server-side against Google's siteverify endpoint.
# - Rejects low-scoring tokens (score < 0.5) with 403.
# - Verifies the file exists in the private GCS bucket.
# - Generates a v4 Signed URL for GET valid for 5 minutes only.
#
# Important environment variables (set on the Cloud Function):
# - RECAPTCHA_SECRET_KEY : the reCAPTCHA v3 secret key (server-only)
# - BUCKET_NAME : GCS bucket (e.g., 'sfe-brands-docs')
#
# Notes about security context passing:
# - The browser (client) executes grecaptcha and receives a short-lived token.
# - The client sends that token with the filename to this function.
# - This function verifies the token with Google (server-to-server) using RECAPTCHA_SECRET_KEY
#   (so the secret never appears in the browser).
# - Only after server-side verification do we check bucket/file and generate a short-lived
#   signed URL which the client may open. The signed URL is cryptographically generated
#   by the service account running the function and is valid for only 5 minutes.
#
import os
import json
from datetime import timedelta
import requests
from google.cloud import storage
from flask import Request

# Only allow this exact origin. All responses will include this origin if the incoming Origin matches.
ALLOWED_ORIGIN = "https://sfeintegrations-coder.github.io/climax-chatbot/"

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

    Expected POST JSON body:
      { "filename": "<path/inside/bucket.pdf>", "recaptcha_token": "<token from grecaptcha.execute()>" }

    Returns JSON:
      { "signed_url": "<google storage signed url>" }

    Error responses include appropriate CORS headers matching the allowed origin.
    """
    # Handle CORS preflight first
    origin = request.headers.get("Origin", "")
    if request.method == "OPTIONS":
        # Only respond positively to OPTIONS if origin exactly matches the configured allowed origin.
        if origin != ALLOWED_ORIGIN:
            return ("", 403, _cors_headers("null"))
        headers = _cors_headers(ALLOWED_ORIGIN)
        headers["Access-Control-Max-Age"] = "3600"
        return ("", 204, headers)

    # Only accept POST for endpoint operation
    if request.method != "POST":
        # for incorrect methods return 405; include CORS header only if origin matches
        allow_origin = ALLOWED_ORIGIN if origin == ALLOWED_ORIGIN else "null"
        return (json.dumps({"error": "Method not allowed"}), 405, _cors_headers(allow_origin))

    # Enforce origin on main requests as well
    if origin != ALLOWED_ORIGIN:
        # Return explicit 403 for disallowed origins and provide a safe CORS header
        return (json.dumps({"error": "Origin not allowed"}), 403, _cors_headers("null"))

    # Parse JSON body
    try:
        payload = request.get_json(silent=True)
    except Exception:
        payload = None

    if not payload or not isinstance(payload, dict):
        return (json.dumps({"error": "Invalid JSON payload"}), 400, _cors_headers(ALLOWED_ORIGIN))

    filename = payload.get("filename")
    recaptcha_token = payload.get("recaptcha_token")

    if not filename or not recaptcha_token:
        return (json.dumps({"error": "Missing 'filename' or 'recaptcha_token'"}), 400, _cors_headers(ALLOWED_ORIGIN))

    # Server-side reCAPTCHA verification (must use secret stored in environment variable)
    RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET_KEY")
    if not RECAPTCHA_SECRET:
        # Misconfiguration — do not proceed if secret is missing
        return (json.dumps({"error": "Server misconfiguration"}), 500, _cors_headers(ALLOWED_ORIGIN))

    # Call Google's reCAPTCHA siteverify endpoint (server-to-server)
    try:
        r = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET, "response": recaptcha_token},
            timeout=5,
        )
    except requests.RequestException:
        return (json.dumps({"error": "reCAPTCHA verification request failed"}), 503, _cors_headers(ALLOWED_ORIGIN))

    if r.status_code != 200:
        return (json.dumps({"error": "reCAPTCHA verification failed"}), 403, _cors_headers(ALLOWED_ORIGIN))

    verification = r.json()
    # verification expected structure:
    # { "success": true|false, "score": float, "action": str, "challenge_ts": "...", "hostname": "..." }
    if not verification.get("success", False):
        return (json.dumps({"error": "reCAPTCHA not successful"}), 403, _cors_headers(ALLOWED_ORIGIN))

    score = float(verification.get("score", 0.0))
    # Enforce threshold (strict): reject anything below 0.5
    if score < 0.5:
        # Treat as bot / suspicious; deny access
        return (json.dumps({"error": "reCAPTCHA score too low"}), 403, _cors_headers(ALLOWED_ORIGIN))

    # Optionally: you can check verification.get("action") if you used an action label on client side

    # Check the file exists in the private GCS bucket
    BUCKET_NAME = os.environ.get("BUCKET_NAME")
    if not BUCKET_NAME:
        return (json.dumps({"error": "Server misconfiguration: BUCKET_NAME missing"}), 500, _cors_headers(ALLOWED_ORIGIN))

    try:
        client = storage.Client()  # uses default credentials (function's service account)
        bucket = client.bucket(BUCKET_NAME)
        blob = bucket.blob(filename)
        # Blob.exists requires a client
        if not blob.exists(client):
            # Do not leak bucket listing; simply say not found
            return (json.dumps({"error": "File not found"}), 404, _cors_headers(ALLOWED_ORIGIN))
    except Exception as e:
        # Unexpected storage error
        return (json.dumps({"error": "Error checking file existence"}), 500, _cors_headers(ALLOWED_ORIGIN))

    # Generate a v4 signed URL with strict 5-minute TTL
    try:
        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=5),
            method="GET",
        )
    except Exception as e:
        return (json.dumps({"error": "Failed to generate signed URL"}), 500, _cors_headers(ALLOWED_ORIGIN))

    # Success: return signed URL as JSON with CORS headers matched to the origin
    response_body = json.dumps({"signed_url": signed_url})
    headers = _cors_headers(ALLOWED_ORIGIN)
    headers["Content-Type"] = "application/json"
    return (response_body, 200, headers)