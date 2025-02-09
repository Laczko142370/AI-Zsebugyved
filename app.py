import os
import pathlib
from flask import Flask, redirect, url_for, session, jsonify, request, render_template
from flask_cors import CORS
from dotenv import load_dotenv
from google.auth.transport import requests
import google.oauth2.id_token
from google_auth_oauthlib.flow import Flow

# Engedélyezzük a HTTP használatát fejlesztői módban
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Betöltjük a .env fájl tartalmát
load_dotenv()

app = Flask(__name__)
CORS(app)

# Google OAuth beállítások
app.secret_key = os.getenv("SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# Hitelesítési áramlás beállítása (Scope hibajavítással)
flow = Flow.from_client_config(
    {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uris": [os.getenv("REDIRECT_URI")],  # Frissítve a .env-ben tárolt URI-ra
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    },
    scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ]
)
flow.redirect_uri = os.getenv("REDIRECT_URI")  # Frissítve a .env-ben tárolt URI-ra

# Alap home route
@app.route("/")
def home():
    return jsonify({"message": "AI-Zsebügyvéd MVP Fejlesztés Elindítva!"})

# Login route
@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url(prompt="consent")
    session["state"] = state
    return redirect(authorization_url)

# Callback route
@app.route("/auth/callback")
def auth_callback():
    flow.fetch_token(authorization_response=request.url)

    if "state" not in session or session["state"] != request.args.get("state"):
        return jsonify({"error": "Invalid state parameter"}), 403

    credentials = flow.credentials
    request_session = requests.Request()
    user_info = google.oauth2.id_token.verify_oauth2_token(
        credentials.id_token, request_session, GOOGLE_CLIENT_ID, clock_skew_in_seconds=20
    )

    return render_template("index.html", name=user_info["name"], picture=user_info["picture"])

# Healthcheck route
@app.route("/healthcheck")
def healthcheck():
    return jsonify({"status": "ok"})

# Futtatás
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)  # Debug módot kikapcsoltuk a production környezethez
