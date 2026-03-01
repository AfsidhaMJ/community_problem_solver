"""
app.py  —  CivicPulse Flask backend
============================================================
• Serves dashboard.html  at  http://localhost:8080/
• Serves authority.html  at  http://localhost:8080/authority
• Runs on port 8080 (matches VS Code launch.json)
• Saves every form field to complaints.json
• Authority accounts stored in authorities.json

Authority credentials (pre-loaded)
-----------------------------------
  username: publicworks      password: pw123
  username: utilities        password: ut123
  username: parks            password: pk123
  username: sanitation       password: sn123
  username: water            password: wa123
  username: emergency        password: em123
  username: admin            password: admin123   (sees ALL complaints)
"""

import json, os, uuid, hashlib, secrets
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DATA_FILE       = os.path.join(BASE_DIR, "complaints.json")
AUTH_FILE       = os.path.join(BASE_DIR, "authorities.json")
FRONTEND_DIR    = BASE_DIR

for path, default in [(DATA_FILE, []), (AUTH_FILE, {})]:
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f)

# ── App ───────────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "civicpulse-dev-secret-change-in-prod")
CORS(app, supports_credentials=True)

# ── Constants ─────────────────────────────────────────────────────────────────

DEPT_MAP = {
    "Roads":      "Public Works",
    "Lighting":   "Utilities Board",
    "Parks":      "Parks & Recreation",
    "Sanitation": "Sanitation Dept.",
    "Water":      "Water Authority",
    "Safety":     "Emergency Services",
}
STATUS_PROGRESS = {"Submitted": 10, "Pending": 20, "In Review": 55, "Escalated": 70, "Resolved": 100}
VALID_CATEGORIES = list(DEPT_MAP.keys())
VALID_PRIORITIES = ["Low", "Medium", "High", "Urgent"]
VALID_STATUSES   = list(STATUS_PROGRESS.keys())

# Default authority accounts  { username: { password_hash, department, name } }
DEFAULT_AUTHORITIES = {
    "publicworks": {
        "name": "Public Works Dept.",
        "department": "Public Works",
        "password_hash": hashlib.sha256("pw123".encode()).hexdigest()
    },
    "utilities": {
        "name": "Utilities Board",
        "department": "Utilities Board",
        "password_hash": hashlib.sha256("ut123".encode()).hexdigest()
    },
    "parks": {
        "name": "Parks & Recreation",
        "department": "Parks & Recreation",
        "password_hash": hashlib.sha256("pk123".encode()).hexdigest()
    },
    "sanitation": {
        "name": "Sanitation Dept.",
        "department": "Sanitation Dept.",
        "password_hash": hashlib.sha256("sn123".encode()).hexdigest()
    },
    "water": {
        "name": "Water Authority",
        "department": "Water Authority",
        "password_hash": hashlib.sha256("wa123".encode()).hexdigest()
    },
    "emergency": {
        "name": "Emergency Services",
        "department": "Emergency Services",
        "password_hash": hashlib.sha256("em123".encode()).hexdigest()
    },
    "admin": {
        "name": "Admin (All Departments)",
        "department": "ALL",
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest()
    },
}

# Seed authorities.json if empty
auth_data = json.loads(open(AUTH_FILE).read())
if not auth_data:
    with open(AUTH_FILE, "w") as f:
        json.dump(DEFAULT_AUTHORITIES, f, indent=2)

# ── Helpers ───────────────────────────────────────────────────────────────────

def load_complaints():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_complaints(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def load_authorities():
    with open(AUTH_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def next_ref(complaints):
    if not complaints:
        return "#1000"
    try:
        last = max(int(c["ref_number"].lstrip("#")) for c in complaints if "ref_number" in c)
        return f"#{last + 1}"
    except (ValueError, AttributeError):
        return f"#{len(complaints) + 1000}"

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

def require_auth(f):
    """Decorator — rejects requests without a valid authority session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authority_user"):
            return jsonify({"success": False, "error": "Unauthorized. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated

def current_authority():
    username = session.get("authority_user")
    if not username:
        return None
    authorities = load_authorities()
    return authorities.get(username)

# ── Serve frontend pages ───────────────────────────────────────────────────────

@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIR, "dashboard.html")

@app.get("/authority")
def authority_portal():
    return send_from_directory(FRONTEND_DIR, "authority.html")

@app.get("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
def login():
    """Authority login. Returns authority info on success."""
    body     = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    password = (body.get("password") or "").strip()

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password are required."}), 400

    authorities = load_authorities()
    account     = authorities.get(username)

    if not account or account["password_hash"] != hash_pw(password):
        return jsonify({"success": False, "error": "Invalid username or password."}), 401

    session["authority_user"] = username
    return jsonify({
        "success":    True,
        "message":    f"Welcome, {account['name']}!",
        "authority":  {
            "username":   username,
            "name":       account["name"],
            "department": account["department"],
        },
    })

@app.post("/api/auth/logout")
def logout():
    session.pop("authority_user", None)
    return jsonify({"success": True, "message": "Logged out."})

@app.get("/api/auth/me")
def me():
    """Return currently logged-in authority info (used on page load)."""
    auth = current_authority()
    username = session.get("authority_user")
    if not auth:
        return jsonify({"success": False, "error": "Not logged in."}), 401
    return jsonify({
        "success": True,
        "authority": {
            "username":   username,
            "name":       auth["name"],
            "department": auth["department"],
        },
    })

# ── Authority complaint routes ────────────────────────────────────────────────

@app.get("/api/authority/complaints")
@require_auth
def authority_complaints():
    """
    Returns complaints assigned to the logged-in authority's department.
    Admin sees all. Others only see their department's complaints.
    """
    auth       = current_authority()
    complaints = load_complaints()

    if auth["department"] != "ALL":
        complaints = [c for c in complaints if c.get("authority") == auth["department"]]

    # Optional filters
    status   = request.args.get("status")
    priority = request.args.get("priority")
    search   = (request.args.get("search") or "").lower()

    if status:
        complaints = [c for c in complaints if c.get("status") == status]
    if priority:
        complaints = [c for c in complaints if c.get("priority") == priority]
    if search:
        complaints = [
            c for c in complaints
            if search in (c.get("title") or "").lower()
            or search in (c.get("location") or "").lower()
        ]

    complaints = sorted(complaints, key=lambda c: c.get("submitted_at", ""), reverse=True)
    return jsonify({"success": True, "total": len(complaints), "data": complaints})


@app.patch("/api/authority/complaints/<complaint_id>/status")
@require_auth
def authority_update_status(complaint_id):
    """
    Authority updates the status of a complaint and adds a timeline note.
    Only the owning department (or admin) may update.
    """
    auth       = current_authority()
    username   = session.get("authority_user")
    body       = request.get_json(silent=True) or {}
    status     = (body.get("status") or "").strip()
    note       = (body.get("note") or "").strip() or None

    if status not in VALID_STATUSES:
        return jsonify({
            "success": False,
            "errors": [f"status must be one of: {', '.join(VALID_STATUSES)}."],
        }), 400

    complaints = load_complaints()
    record     = next((c for c in complaints if c.get("id") == complaint_id), None)

    if not record:
        return jsonify({"success": False, "error": "Complaint not found."}), 404

    # Department check
    if auth["department"] != "ALL" and record.get("authority") != auth["department"]:
        return jsonify({"success": False, "error": "You can only update complaints assigned to your department."}), 403

    ts = now_iso()
    record["status"]     = status
    record["progress"]   = STATUS_PROGRESS.get(status, 20)
    record["updated_at"] = ts
    record.setdefault("timeline", []).append({
        "event":       status.lower().replace(" ", "_"),
        "label":       status,
        "description": note or f"Status updated to '{status}' by {auth['name']}",
        "updated_by":  auth["name"],
        "timestamp":   ts,
    })

    save_complaints(complaints)
    return jsonify({
        "success": True,
        "message": f"Status updated to '{status}'.",
        "data":    record,
    })


@app.post("/api/authority/complaints/<complaint_id>/note")
@require_auth
def authority_add_note(complaint_id):
    """Authority adds a public progress note to a complaint's timeline."""
    auth     = current_authority()
    body     = request.get_json(silent=True) or {}
    label    = (body.get("label") or "").strip()
    desc     = (body.get("description") or "").strip() or None

    if len(label) < 3:
        return jsonify({"success": False, "errors": ["label is required (min 3 characters)."]}), 400

    complaints = load_complaints()
    record     = next((c for c in complaints if c.get("id") == complaint_id), None)

    if not record:
        return jsonify({"success": False, "error": "Complaint not found."}), 404

    if auth["department"] != "ALL" and record.get("authority") != auth["department"]:
        return jsonify({"success": False, "error": "Access denied."}), 403

    ts = now_iso()
    event = {
        "event":       "note",
        "label":       label,
        "description": desc,
        "updated_by":  auth["name"],
        "timestamp":   ts,
    }
    record.setdefault("timeline", []).append(event)
    record["updated_at"] = ts

    save_complaints(complaints)
    return jsonify({"success": True, "message": "Note added.", "data": event}), 201


@app.get("/api/authority/stats")
@require_auth
def authority_stats():
    """Stats scoped to the logged-in authority's department."""
    auth       = current_authority()
    complaints = load_complaints()

    if auth["department"] != "ALL":
        complaints = [c for c in complaints if c.get("authority") == auth["department"]]

    by_status   = {}
    by_priority = {}
    for c in complaints:
        s = c.get("status",   "Unknown")
        p = c.get("priority", "Unknown")
        by_status[s]   = by_status.get(s, 0) + 1
        by_priority[p] = by_priority.get(p, 0) + 1

    total = len(complaints)
    return jsonify({
        "success": True,
        "data": {
            "total":       total,
            "open":        total - by_status.get("Resolved", 0),
            "resolved":    by_status.get("Resolved", 0),
            "urgent":      by_priority.get("Urgent", 0),
            "by_status":   by_status,
            "by_priority": by_priority,
        },
    })

# ── Public citizen routes (unchanged) ─────────────────────────────────────────

@app.post("/api/report")
def report_issue():
    body   = request.get_json(silent=True) or {}
    errors = []

    full_name = (body.get("full_name") or "").strip()
    if len(full_name) < 2:
        errors.append("full_name is required (min 2 characters).")

    contact = (body.get("contact") or "").strip()
    if len(contact) < 3:
        errors.append("contact (email or phone) is required.")

    category = (body.get("category") or "").strip()
    if category not in VALID_CATEGORIES:
        errors.append(f"category must be one of: {', '.join(VALID_CATEGORIES)}.")

    title = (body.get("title") or "").strip()
    if len(title) < 5:
        errors.append("title is required (min 5 characters).")

    location = (body.get("location") or "").strip()
    if len(location) < 3:
        errors.append("location is required.")

    priority = (body.get("priority") or "Medium").strip()
    if priority not in VALID_PRIORITIES:
        errors.append(f"priority must be one of: {', '.join(VALID_PRIORITIES)}.")

    if errors:
        return jsonify({"success": False, "errors": errors}), 400

    complaints = load_complaints()
    authority  = DEPT_MAP.get(category, "Municipality")
    ts         = now_iso()

    complaint = {
        "id":             str(uuid.uuid4())[:8],
        "ref_number":     next_ref(complaints),
        "full_name":      full_name,
        "contact":        contact,
        "category":       category,
        "category_emoji": (body.get("category_emoji") or "").strip(),
        "title":          title,
        "location":       location,
        "description":    (body.get("description") or "").strip() or None,
        "priority":       priority,
        "authority":      authority,
        "status":         "Submitted",
        "progress":       STATUS_PROGRESS["Submitted"],
        "submitted_at":   ts,
        "updated_at":     ts,
        "timeline": [
            {"event": "submitted",  "label": "Report Submitted",       "description": f"Submitted by {full_name}", "timestamp": ts},
            {"event": "dispatched", "label": f"Sent to {authority}",   "description": "Automatically routed to the relevant authority", "timestamp": ts},
        ],
    }

    complaints.append(complaint)
    save_complaints(complaints)
    return jsonify({"success": True, "message": "Complaint submitted successfully.", "data": complaint}), 201


@app.get("/api/complaints")
def get_complaints():
    complaints = load_complaints()
    status   = request.args.get("status")
    priority = request.args.get("priority")
    category = request.args.get("category")
    search   = (request.args.get("search") or "").lower()
    if status:   complaints = [c for c in complaints if c.get("status") == status]
    if priority: complaints = [c for c in complaints if c.get("priority") == priority]
    if category: complaints = [c for c in complaints if c.get("category") == category]
    if search:
        complaints = [c for c in complaints if
            search in (c.get("title") or "").lower() or
            search in (c.get("location") or "").lower() or
            search in (c.get("full_name") or "").lower()]
    return jsonify({"success": True, "total": len(complaints), "data": complaints})


@app.get("/api/complaints/<complaint_id>")
def get_complaint(complaint_id):
    record = next((c for c in load_complaints() if c.get("id") == complaint_id), None)
    if not record:
        return jsonify({"success": False, "error": "Complaint not found."}), 404
    return jsonify({"success": True, "data": record})


@app.get("/api/stats")
def get_stats():
    complaints = load_complaints()
    by_status = {}; by_priority = {}; by_category = {}
    for c in complaints:
        s = c.get("status","Unknown"); p = c.get("priority","Unknown"); k = c.get("category","Unknown")
        by_status[s] = by_status.get(s,0)+1
        by_priority[p] = by_priority.get(p,0)+1
        by_category[k] = by_category.get(k,0)+1
    total = len(complaints)
    return jsonify({"success": True, "data": {
        "total": total, "open": total - by_status.get("Resolved",0),
        "resolved": by_status.get("Resolved",0), "urgent": by_priority.get("Urgent",0),
        "by_status": by_status, "by_priority": by_priority, "by_category": by_category,
    }})


@app.get("/api/health")
def health():
    return jsonify({"success": True, "status": "ok", "timestamp": now_iso()})

@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Route not found."}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"success": False, "error": "Method not allowed."}), 405

if __name__ == "__main__":
    print("\n🌿 CivicPulse running at http://localhost:8080")
    print("   Authority portal → http://localhost:8080/authority")
    print("   complaints.json  →", DATA_FILE)
    print("   authorities.json →", AUTH_FILE)
    print("\n   Default logins:")
    print("   admin / admin123   (all departments)")
    print("   publicworks / pw123")
    print("   utilities / ut123\n")
    app.run(debug=True, port=8080)
