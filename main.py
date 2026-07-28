# main.py
#
# Google Cloud Function (Gen 2, Python 3.11)
# Entry point: get_secure_file_url
#
import os
import json
from datetime import timedelta
import requests
import google.auth
from google.auth import impersonated_credentials
from google.cloud import storage
from flask import Request

# Restrict CORS to your actual frontend origin instead of "*".
# Set this via an env var so you don't have to hardcode/redeploy on change.
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://vaishnavikulk2000-maker.github.io")

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
    Cloud Function entry point. Wrapped so that even an unexpected
    exception still returns a response with CORS headers, instead of
    letting the platform return a bare 500 with no headers at all
    (which the browser reports as an opaque CORS failure).
    """
    try:
        return _handle_request(request)
    except Exception as e:
        print(f"Unhandled exception in get_secure_file_url: {e}")
        return (json.dumps({"error": "Internal server error"}), 500, _cors_headers(ALLOWED_ORIGIN))


def _handle_request(request: Request):
    # Handle CORS preflight first with wildcard to eliminate browser blocks
    if request.method == "OPTIONS":
        headers = _cors_headers(ALLOWED_ORIGIN)
        headers["Access-Control-Max-Age"] = "3600"
        return ("", 204, headers)

    # Only accept POST for endpoint operation
    if request.method != "POST":
        return (json.dumps({"error": "Method not allowed"}), 405, _cors_headers(ALLOWED_ORIGIN))

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

    # Server-side reCAPTCHA verification
    RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET_KEY")
    if not RECAPTCHA_SECRET:
        return (json.dumps({"error": "Server misconfiguration"}), 500, _cors_headers(ALLOWED_ORIGIN))

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
    if not verification.get("success", False):
        return (json.dumps({"error": "reCAPTCHA not successful"}), 403, _cors_headers(ALLOWED_ORIGIN))

    score = float(verification.get("score", 0.0))
    if score < 0.5:
        return (json.dumps({"error": "reCAPTCHA score too low"}), 403, _cors_headers(ALLOWED_ORIGIN))

    # Check the file exists in the private GCS bucket
    BUCKET_NAME = os.environ.get("BUCKET_NAME")
    if not BUCKET_NAME:
        return (json.dumps({"error": "Server misconfiguration: BUCKET_NAME missing"}), 500, _cors_headers(ALLOWED_ORIGIN))

    try:
        client = storage.Client()
        bucket = client.bucket(BUCKET_NAME)
        blob = bucket.blob(filename)
        if not blob.exists(client):
            return (json.dumps({"error": "File not found"}), 404, _cors_headers(ALLOWED_ORIGIN))
    except Exception as e:
        return (json.dumps({"error": "Error checking file existence"}), 500, _cors_headers(ALLOWED_ORIGIN))

    # Generate a v4 signed URL with strict 5-minute TTL.
    #
    # NOTE: Cloud Functions/Cloud Run's default runtime credentials
    # (google.auth.compute_engine.Credentials) only carry a short-lived
    # access token, not a private key, so they cannot sign locally.
    # We use IAM's signBlob API via impersonated credentials instead —
    # this requires the function's runtime service account to have
    # `roles/iam.serviceAccountTokenCreator` granted on ITSELF.
    try:
        source_credentials, _ = google.auth.default()
        signer_email = os.environ.get("SIGNER_SERVICE_ACCOUNT")
        if not signer_email:
            return (json.dumps({"error": "Server misconfiguration: SIGNER_SERVICE_ACCOUNT missing"}), 500, _cors_headers(ALLOWED_ORIGIN))

        signing_credentials = impersonated_credentials.Credentials(
            source_credentials=source_credentials,
            target_principal=signer_email,
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
            lifetime=300,
        )

        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=5),
            method="GET",
            credentials=signing_credentials,
        )
    except Exception as e:
        print(f"Signed URL generation failed: {e}")
        return (json.dumps({"error": "Failed to generate signed URL"}), 500, _cors_headers(ALLOWED_ORIGIN))

    # Success: return signed URL as JSON with CORS headers
    response_body = json.dumps({"signed_url": signed_url})
    headers = _cors_headers(ALLOWED_ORIGIN)
    headers["Content-Type"] = "application/json"
    return (response_body, 200, headers)