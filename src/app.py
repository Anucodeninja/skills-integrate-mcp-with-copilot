"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pathlib import Path
from pydantic import BaseModel

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

TEACHERS_FILE = Path(os.environ.get(
    "TEACHER_ACCOUNTS_FILE", current_dir / "teachers.json"
))
SESSION_COOKIE = "teacher_session"
SESSION_DURATION_SECONDS = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 310_000
SESSION_SECRET = os.environ.get("TEACHER_SESSION_SECRET")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_bytes(32)
else:
    SESSION_SECRET = SESSION_SECRET.encode("utf-8")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


class LoginRequest(BaseModel):
    username: str
    password: str


def hash_teacher_password(password: str) -> dict[str, str]:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return {"salt": salt.hex(), "password_hash": password_hash.hex()}


def _load_teacher_accounts() -> dict[str, dict[str, str]]:
    try:
        data = json.loads(TEACHERS_FILE.read_text(encoding="utf-8"))
        records = data.get("teachers", [])
    except (OSError, json.JSONDecodeError, AttributeError):
        return {}

    if not isinstance(records, list):
        return {}

    accounts = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        username = record.get("username")
        salt = record.get("salt")
        password_hash = record.get("password_hash")
        if all(isinstance(value, str) and value for value in (username, salt, password_hash)):
            accounts[username.casefold()] = record
    return accounts


def _verify_teacher_password(username: str, password: str) -> str | None:
    account = _load_teacher_accounts().get(username.casefold())
    if account is None:
        return None

    try:
        salt = bytes.fromhex(account["salt"])
        expected_hash = bytes.fromhex(account["password_hash"])
    except ValueError:
        return None

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    if not hmac.compare_digest(actual_hash, expected_hash):
        return None
    return account["username"]


def _create_session_token(username: str) -> str:
    expires_at = int(time.time()) + SESSION_DURATION_SECONDS
    payload = base64.urlsafe_b64encode(
        f"{username}\n{expires_at}".encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(
        SESSION_SECRET, payload.encode("ascii"), hashlib.sha256
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{payload}.{encoded_signature}"


def _get_session_username(token: str | None) -> str | None:
    if not token or "." not in token:
        return None

    payload, encoded_signature = token.rsplit(".", 1)
    try:
        expected_signature = hmac.new(
            SESSION_SECRET, payload.encode("ascii"), hashlib.sha256
        ).digest()
        signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
        decoded_payload = base64.urlsafe_b64decode(
            payload + "=" * (-len(payload) % 4)
        ).decode("utf-8")
        username, expires_at = decoded_payload.rsplit("\n", 1)
        if not hmac.compare_digest(signature, expected_signature):
            return None
        if int(expires_at) <= int(time.time()):
            return None
    except (ValueError, UnicodeError):
        return None
    return username


def require_teacher(request: Request) -> str:
    username = _get_session_username(request.cookies.get(SESSION_COOKIE))
    if username is None:
        raise HTTPException(status_code=401, detail="Teacher sign-in required")
    return username


@app.post("/auth/login")
def login(credentials: LoginRequest, response: Response, request: Request):
    username = _verify_teacher_password(credentials.username, credentials.password)
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response.set_cookie(
        key=SESSION_COOKIE,
        value=_create_session_token(username),
        max_age=SESSION_DURATION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )
    return {"authenticated": True, "username": username}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"authenticated": False}


@app.get("/auth/status")
def auth_status(request: Request):
    username = _get_session_username(request.cookies.get(SESSION_COOKIE))
    return {"authenticated": username is not None, "username": username}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str, email: str, teacher: str = Depends(require_teacher)
):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str, email: str, teacher: str = Depends(require_teacher)
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
