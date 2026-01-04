from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file,
    jsonify,
)
from sqlalchemy import text
from models import db, User, Class, Portfolio, Candidate, Vote, Election
import os
import hashlib

# optional server-side session support
try:
    from flask_session import Session
    HAS_FLASK_SESSION = True
except Exception:
    HAS_FLASK_SESSION = False

import pickle

# optional image processing
try:
    from PIL import Image, ImageOps
    HAS_PIL = True
except Exception:
    HAS_PIL = False

import pandas as pd
from io import BytesIO
from datetime import datetime
import json
from markupsafe import Markup


# ------------------ APP INIT (FIX IS HERE) ------------------

app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")

# ✅ FIXED: app exists before using app.config
app.config.setdefault("CANDIDATE_PHOTO_SIZE", (400, 400))


app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")

db.init_app(app)

import json
from markupsafe import Markup

def _escapejs_filter(s):
    if s is None:
        return ''
    return Markup(json.dumps(str(s)))

app.jinja_env.filters['escapejs'] = _escapejs_filter

# Ensure `tojson` exists on older Jinja/Flask versions
if 'tojson' not in app.jinja_env.filters:
    app.jinja_env.filters['tojson'] = lambda s: Markup(json.dumps(s))


def _current_device_password_hash():
    e = Election.query.first()
    if not e or not e.device_password:
        return None
    return hashlib.sha256(str(e.device_password).encode()).hexdigest()


def is_device_authenticated():
    # check that session indicates auth and the stored password hash matches the current election device password
    if not session.get('device_authenticated'):
        return False
    stored = session.get('device_password_hash')
    current = _current_device_password_hash()
    return stored is not None and current is not None and stored == current

# Optional: initialize server-side session store if Flask-Session is available
if HAS_FLASK_SESSION:
    # Default to filesystem session store under the instance folder
    app.config.setdefault('SESSION_TYPE', 'filesystem')
    app.config.setdefault('SESSION_FILE_DIR', os.path.join(app.instance_path or app.root_path, 'flask_session'))
    app.config.setdefault('SESSION_PERMANENT', False)
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    Session(app)


def clear_all_sessions(keep_admin=True):
    """Clear server-side stored session files (if filesystem session store is used).
    Attempts to preserve sessions where 'role' == 'admin' when keep_admin=True.
    """
    if not HAS_FLASK_SESSION:
        # Nothing to do when Flask-Session isn't enabled
        return

    session_dir = app.config.get('SESSION_FILE_DIR')
    if not session_dir or not os.path.isdir(session_dir):
        return

    for fname in os.listdir(session_dir):
        path = os.path.join(session_dir, fname)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, 'rb') as f:
                data = f.read()
            # attempt to unpickle session data to inspect role
            try:
                sess_obj = pickle.loads(data)
            except Exception:
                sess_obj = None

            role = None
            if isinstance(sess_obj, dict):
                role = sess_obj.get('role')
            # if we should keep admin sessions and this file belongs to an admin, skip deletion
            if keep_admin and role == 'admin':
                continue
        except Exception:
            # if we can't inspect, fall through and delete the file to be safe
            pass

        try:
            os.remove(path)
        except Exception:
            pass


# Image resize helper for candidate photos (uses Pillow if available)
def _resize_image(path, size=None):
    if not HAS_PIL:
        return False
    size = size or tuple(app.config.get('CANDIDATE_PHOTO_SIZE', (400, 400)))
    try:
        with Image.open(path) as im:
            # respect EXIF orientation
            im = ImageOps.exif_transpose(im)
            # fit and crop to size
            im = ImageOps.fit(im, size, Image.LANCZOS)
            # choose format based on extension
            ext = os.path.splitext(path)[1].lower()
            fmt = 'PNG' if ext == '.png' else 'JPEG'
            # convert to RGB for JPEG
            if fmt == 'JPEG':
                im = im.convert('RGB')
                im.save(path, format=fmt, optimize=True, quality=85)
            else:
                im.save(path, format=fmt, optimize=True)
        return True
    except Exception:
        return False

# ------------------ ROUTES ------------------


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form.get("password")

        # Check admin
        admin = User.query.filter_by(index_number=username, role="admin").first()
        if admin and admin.password == password:
            session["role"] = "admin"
            # set transient flag so the login page can show an admin choice modal
            session["admin_after_login"] = True
            return redirect(url_for("login"))

        # Check voter
        voter = User.query.filter_by(
            index_number=username, role="voter", is_deleted=False
        ).first()
        if voter:
            session["voter_id"] = voter.id
            return redirect(url_for("voter_device_check"))
        flash("Invalid login", "danger")

    # If admin just logged in, show them the post-login choice modal once
    show_admin_modal = session.pop('admin_after_login', False)
    e = Election.query.first()
    return render_template("login.html", show_admin_modal=show_admin_modal, election=e)


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    # Admin logout clears the whole session; voter logout only removes voter-specific keys but keeps device authentication active
    if session.get('role') == 'admin':
        session.clear()
    else:
        session.pop('voter_id', None)
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))


# ---------------- ADMIN DASHBOARD ----------------


@app.route("/admin/dashboard")
def admindashboard():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    stats = {
        "students": User.query.filter_by(role="voter").count(),
        "classes": Class.query.count(),
        "portfolios": Portfolio.query.count(),
        "candidates": Candidate.query.count(),
        "votes": Vote.query.count(),
    }

    election = Election.query.first()

    return render_template("admindashboard.html", stats=stats, election=election)


# ---------------- STUDENTS ----------------
@app.route("/admin/students", methods=["GET", "POST"])
def view_students():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    classes = Class.query.order_by(Class.year, Class.name).all()
    selected_class = request.args.get("class_id")
    selected_year = request.args.get("year")

    # Base query: only voters and not soft-deleted
    query = User.query.filter_by(role="voter", is_deleted=False)

    if selected_class:
        query = query.filter_by(class_id=selected_class)
    if selected_year:
        class_ids = [c.id for c in Class.query.filter_by(year=selected_year).all()]
        query = query.filter(User.class_id.in_(class_ids))

    students = query.order_by(User.index_number).all()

    return render_template(
        "students.html",
        students=students,
        classes=classes,
        selected_class=selected_class,
        selected_year=selected_year,
    )


@app.route("/admin/students/add", methods=["GET", "POST"])
def add_student():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    classes = Class.query.order_by(Class.year, Class.name).all()

    if request.method == "POST":
        name = request.form.get("name")
        sex = request.form.get("sex")
        class_id = request.form.get("class_id")

        if not class_id or not name:
            flash("Please provide all required fields", "danger")
            return redirect(url_for("add_student"))

        classroom = Class.query.get(class_id)
        year_prefix = str(classroom.year)[-2:]  # last 2 digits of year

        # Get last student in that year
        last_student = (
            User.query.filter(User.index_number.like(f"{year_prefix}%"))
            .order_by(User.index_number.desc())
            .first()
        )
        seed = (
            int(year_prefix + "0001")
            if not last_student
            else int(last_student.index_number) + 1
        )

        index_number = str(seed).zfill(6)

        student = User(
            index_number=index_number,
            name=name,
            sex=sex,
            password="",  # optional default password
            role="voter",
            class_id=class_id,
        )
        db.session.add(student)
        db.session.commit()

        flash(f"Student added successfully with index number {index_number}", "success")
        return redirect(url_for("view_students"))

    return render_template("add_student.html", classes=classes)


@app.route("/admin/students/upload", methods=["POST"])
def upload_students():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    file = request.files.get("file")
    class_id = request.form.get("class_id")

    if not file or not class_id:
        flash("Missing file or class", "danger")
        return redirect(url_for("view_students"))

    classroom = Class.query.get(class_id)
    if not classroom:
        flash("Invalid class selected.", "danger")
        return redirect(url_for("view_students"))

    # Read file (support XLSX/XLS/CSV) and validate headers
    filename = (file.filename or "").lower()
    try:
        if filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file)
    except Exception as e:
        flash(f"Unable to read uploaded file: {e}", "danger")
        return redirect(url_for("view_students"))

    # Normalize headers and auto-detect common synonyms for validation (e.g. fullname -> name, gender -> sex)
    def _norm(s):
        return ''.join(ch for ch in (s or '').lower() if ch.isalnum())

    cols = list(df.columns)
    norm_map = {_norm(c): c for c in cols}

    synonyms = {
        'name': ['name', 'fullname', 'full name', 'full_name', 'studentname', 'student name', 'full-name', 'firstlast', 'firstname', 'last_name', 'lastname', 'fullnam'],
        'sex': ['sex', 'gender', 'g', 'genderidentity', 'gender identity'],
    }

    mapped = {}
    for std, variants in synonyms.items():
        for v in variants:
            key = _norm(v)
            if key in norm_map:
                mapped[std] = norm_map[key]
                break

    # Ensure explicit 'name' column is found even if not matched by synonyms
    if 'name' not in mapped:
        for c in cols:
            if c.lower().strip() == 'name':
                mapped['name'] = c
                break

    # 'name' is required; 'sex' remains optional
    if 'name' not in mapped:
        detected = ', '.join(cols) if cols else 'none'
        flash(
            f"Uploaded file is missing required column 'name'. Detected columns: {detected}. Expected at minimum: name (sex optional). Make sure your file has a header row with column 'name' (or 'fullname').",
            "danger",
        )
        return redirect(url_for("view_students"))

    name_col = mapped['name']
    sex_col = mapped.get('sex')

    # Prepare seed based on year prefix
    year_prefix = str(classroom.year)[-2:]

    # Get last student in that year
    last_student = (
        User.query.filter(User.index_number.like(f"{year_prefix}%"))
        .order_by(User.index_number.desc())
        .first()
    )

    # Start at XX0001 if no student exists
    seed = (
        int(year_prefix + "0001")
        if not last_student
        else int(last_student.index_number) + 1
    )

    added = 0
    for _, row in df.iterrows():
        name = str(row.get(name_col) or "").strip()
        if not name:
            # skip empty rows
            continue
        sex = row.get(sex_col, "Not set") if sex_col else "Not set"

        index_number = str(seed).zfill(6)

        student = User(
            index_number=index_number,
            name=name,
            sex=sex,
            password="",
            role="voter",
            class_id=class_id,
        )
        db.session.add(student)
        seed += 1
        added += 1

    if added == 0:
        flash("No valid student rows found in the uploaded file.", "warning")
        return redirect(url_for("view_students"))

    db.session.commit()
    flash(f"{added} students uploaded successfully with 6-digit index numbers.", "success")
    return redirect(url_for("view_students"))


@app.route("/admin/students/sample")
def download_students_sample():
    # only admins may download the sample
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    class_id = request.args.get('class_id')
    year = request.args.get('year')

    if not class_id or not year:
        flash("Please select both Year and Class to download the sample file.", "danger")
        return redirect(url_for("view_students"))

    classroom = Class.query.get(class_id)
    if not classroom:
        flash("Invalid class selected.", "danger")
        return redirect(url_for("view_students"))

    if str(classroom.year) != str(year):
        flash("Selected class does not match the chosen year.", "danger")
        return redirect(url_for("view_students"))

    # sample columns must match the upload expectations
    df = pd.DataFrame([
        {"name": "Daniel Dravie", "sex": "Male"},
        {"name": "Daniella Dravie", "sex": "Female"},
    ])

    output = BytesIO()
    filename_base = f"sample_students_{classroom.name}_{classroom.year}"
    # try to produce an .xlsx file; fall back to CSV if engine not available
    try:
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="students")
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name=f"{filename_base}.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception:
        output = BytesIO()
        df.to_csv(output, index=False)
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name=f"{filename_base}.csv",
            mimetype="text/csv",
        )


# ---------------- STUDENT CRUD ----------------
@app.route("/admin/students/<int:student_id>/edit", methods=["GET", "POST"])
def edit_student(student_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    student = User.query.get_or_404(student_id)
    classes = Class.query.order_by(Class.year, Class.name).all()

    if request.method == "POST":
        student.name = request.form.get("name")
        student.sex = request.form.get("sex")
        class_id = request.form.get("class_id")
        student.class_id = int(class_id) if class_id else None
        db.session.commit()
        flash("Student updated successfully", "success")
        return redirect(url_for("view_students"))

    return render_template("edit_student.html", student=student, classes=classes)


@app.route("/admin/students/<int:student_id>/delete", methods=["POST"])
def delete_student(student_id):
    # keep old behavior (form POST) compatible but make it soft-delete
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    student = User.query.get_or_404(student_id)
    student.is_deleted = True
    db.session.commit()
    # if AJAX request, return JSON
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
        return jsonify({"success": True})
    flash("Student deleted (can be undone)", "info")
    return redirect(url_for("view_students"))


@app.route("/admin/students/<int:student_id>/undo", methods=["POST"])
def undo_delete_student(student_id):
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 403
    student = User.query.get_or_404(student_id)
    student.is_deleted = False
    db.session.commit()
    return jsonify(
        {"success": True, "student": {"id": student.id, "name": student.name}}
    )


# ---------------- STUDENT API (inline edit) ----------------
@app.route("/admin/students/<int:student_id>/api", methods=["POST"])
def api_edit_student(student_id):
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 403
    data = request.get_json() or {}
    student = User.query.get_or_404(student_id)
    name = data.get("name")
    sex = data.get("sex")
    class_id = data.get("class_id")
    if name is not None:
        student.name = name
    if sex is not None:
        student.sex = sex
    if class_id is not None:
        student.class_id = int(class_id) if class_id != "" else None
    db.session.commit()
    return jsonify(
        {
            "success": True,
            "student": {
                "id": student.id,
                "name": student.name,
                "sex": student.sex,
                "class": student.classroom.name if student.classroom else None,
            },
        }
    )


# ---------------- CANDIDATE CRUD ----------------
@app.route("/admin/candidates/<int:candidate_id>/edit", methods=["GET", "POST"])
def edit_candidate(candidate_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    candidate = Candidate.query.get_or_404(candidate_id)
    portfolios = Portfolio.query.all()
    classes = Class.query.all()

    if request.method == "POST":
        candidate.portfolio_id = int(request.form.get("portfolio_id"))
        # handle optional photo replacement
        photo_file = request.files.get('photo')
        if photo_file and photo_file.filename:
            from werkzeug.utils import secure_filename
            import uuid
            ALLOWED_EXT = {'.png', '.jpg', '.jpeg', '.gif'}
            fname = secure_filename(photo_file.filename)
            _, ext = os.path.splitext(fname.lower())
            if ext not in ALLOWED_EXT:
                flash('Unsupported image format. Allowed: png, jpg, jpeg, gif', 'danger')
                return redirect(url_for('edit_candidate', candidate_id=candidate_id))
            unique = f"{uuid.uuid4().hex}{ext}"
            dest_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'candidates')
            os.makedirs(dest_dir, exist_ok=True)
            dest_path = os.path.join(dest_dir, unique)
            photo_file.save(dest_path)
            # attempt to resize for consistent thumbnails
            try:
                _resize_image(dest_path)
            except Exception:
                pass
            # delete old photo file if present
            if candidate.photo:
                try:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], candidate.photo)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                except Exception:
                    pass
            candidate.photo = f"candidates/{unique}"

        db.session.commit()
        flash("Candidate updated successfully", "success")
        return redirect(url_for("view_candidates"))

    return render_template(
        "edit_candidate.html",
        candidate=candidate,
        portfolios=portfolios,
        classes=classes,
    )


@app.route("/admin/candidates/<int:candidate_id>/delete", methods=["POST"])
def delete_candidate(candidate_id):
    # soft-delete for compatibility
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    candidate = Candidate.query.get_or_404(candidate_id)
    candidate.is_deleted = True
    db.session.commit()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
        return jsonify({"success": True})
    flash("Candidate deleted (can be undone)", "info")
    return redirect(url_for("view_candidates"))


@app.route("/admin/candidates/<int:candidate_id>/undo", methods=["POST"])
def undo_delete_candidate(candidate_id):
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 403
    candidate = Candidate.query.get_or_404(candidate_id)
    candidate.is_deleted = False
    db.session.commit()
    return jsonify(
        {
            "success": True,
            "candidate": {
                "id": candidate.id,
                "portfolio": candidate.portfolio.name if candidate.portfolio else None,
            },
        }
    )


# ---------------- CANDIDATE API (inline edit) ----------------
@app.route("/admin/candidates/<int:candidate_id>/api", methods=["POST"])
def api_edit_candidate(candidate_id):
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 403
    data = request.get_json() or {}
    candidate = Candidate.query.get_or_404(candidate_id)
    portfolio_id = data.get("portfolio_id")
    if portfolio_id is not None:
        candidate.portfolio_id = int(portfolio_id)
        db.session.commit()
    return jsonify(
        {
            "success": True,
            "candidate": {
                "id": candidate.id,
                "portfolio": candidate.portfolio.name if candidate.portfolio else None,
            },
        }
    )


@app.route("/admin/candidates", methods=["GET", "POST"])
def view_candidates():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    portfolios = Portfolio.query.all()
    classes = Class.query.all()

    voter_info = None

    # Fetch voter details by index number (AJAX or POST)
    if request.method == "POST" and "index_number" in request.form:
        index_number = request.form.get("index_number")
        voter = User.query.filter_by(
            index_number=index_number, role="voter", is_deleted=False
        ).first()
        if voter:
            voter_info = voter
        else:
            flash("Voter not found", "danger")

    # Final submission: register candidate
    if request.method == "POST" and "portfolio_id" in request.form:
        index_number = request.form.get("index_number")
        portfolio_id = request.form.get("portfolio_id")
        voter = User.query.filter_by(
            index_number=index_number, role="voter", is_deleted=False
        ).first()
        if not voter:
            flash("Voter not found", "danger")
            return redirect(url_for("view_candidates"))

        # Check if already a candidate in that portfolio
        existing = Candidate.query.filter_by(
            portfolio_id=portfolio_id, user_id=voter.id
        ).first()
        if existing:
            flash("Candidate already registered for this portfolio", "warning")
            return redirect(url_for("view_candidates"))

        candidate = Candidate(
            user_id=voter.id, portfolio_id=portfolio_id, class_id=voter.class_id
        )
        # handle photo upload
        photo_file = request.files.get('photo')
        if photo_file and photo_file.filename:
            from werkzeug.utils import secure_filename
            import uuid
            ALLOWED_EXT = {'.png', '.jpg', '.jpeg', '.gif'}
            fname = secure_filename(photo_file.filename)
            _, ext = os.path.splitext(fname.lower())
            if ext not in ALLOWED_EXT:
                flash('Unsupported image format. Allowed: png, jpg, jpeg, gif', 'danger')
                return redirect(url_for('view_candidates'))
            # generate unique filename
            unique = f"{uuid.uuid4().hex}{ext}"
            dest_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'candidates')
            os.makedirs(dest_dir, exist_ok=True)
            dest_path = os.path.join(dest_dir, unique)
            photo_file.save(dest_path)
            # attempt to resize for consistent thumbnails
            try:
                _resize_image(dest_path)
            except Exception:
                pass
            # store relative path under uploads/candidates/
            candidate.photo = f"candidates/{unique}"

        db.session.add(candidate)
        db.session.commit()
        flash(f"Candidate {voter.name} registered successfully", "success")
        return redirect(url_for("view_candidates"))

    candidates = Candidate.query.filter_by(is_deleted=False).all()
    return render_template(
        "candidates.html",
        candidates=candidates,
        portfolios=portfolios,
        classes=classes,
        voter_info=voter_info,
    )


@app.route('/admin/candidates/export')
def export_candidates():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    output = BytesIO()
    writer = pd.ExcelWriter(output, engine='openpyxl')

    for portfolio in Portfolio.query.order_by(Portfolio.name).all():
        data = []
        for candidate in portfolio.candidates:
            if getattr(candidate, 'is_deleted', False):
                continue
            data.append({
                'Candidate': candidate.user.name if candidate.user else 'N/A',
                'Index Number': candidate.user.index_number if candidate.user else 'N/A',
                'Class': candidate.classroom.name if candidate.classroom else 'N/A',
                'Photo': candidate.photo if candidate.photo else '',
            })
        if data:
            df = pd.DataFrame(data)
            df.to_excel(writer, sheet_name=portfolio.name[:31], index=False)

    writer.close()
    output.seek(0)
    return send_file(output, as_attachment=True, download_name='candidates_by_portfolio.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/admin/candidates/print')
def print_candidates():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    portfolios = Portfolio.query.order_by(Portfolio.name).all()
    # Filter candidates per portfolio and exclude deleted
    return render_template('candidates_print.html', portfolios=portfolios)


# ---------------- RESULTS (ADMIN) ----------------
@app.route("/admin/results")
def view_results():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    portfolios = Portfolio.query.all()

    # Optional filter by portfolio_id from query string
    selected_id_param = request.args.get("portfolio_id", type=int)
    selected_portfolio = None
    winner_ids = set()

    # Pre-compute votes & winners for each portfolio
    for portfolio in portfolios:
        visible_candidates = [
            c for c in portfolio.candidates if not getattr(c, "is_deleted", False)
        ]
        for c in visible_candidates:
            c.votes = Vote.query.filter_by(candidate_id=c.id).count()

        if visible_candidates:
            max_votes = max(c.votes for c in visible_candidates)
            portfolio.winners = [c for c in visible_candidates if c.votes == max_votes]
        else:
            portfolio.winners = []

        # Find the currently selected portfolio object
        if selected_id_param and portfolio.id == selected_id_param:
            selected_portfolio = portfolio

    if selected_portfolio:
        winner_ids = {c.id for c in getattr(selected_portfolio, "winners", [])}

    return render_template(
        "results.html",
        portfolios=portfolios,
        selected_portfolio=selected_portfolio,
        selected_portfolio_id=selected_id_param,
        winner_ids=winner_ids,
    )


@app.route("/admin/export")
def export_results():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    output = BytesIO()
    writer = pd.ExcelWriter(output, engine="openpyxl")

    # Loop through all portfolios
    for portfolio in Portfolio.query.all():
        data = []
        for candidate in portfolio.candidates:
            if getattr(candidate, "is_deleted", False):
                continue
            votes_count = Vote.query.filter_by(candidate_id=candidate.id).count()
            data.append(
                {
                    "Candidate": candidate.user.name if candidate.user else "N/A",
                    "Class": candidate.classroom.name if candidate.classroom else "N/A",
                    "Votes": votes_count,
                }
            )
        if data:
            df = pd.DataFrame(data)
            df = df.sort_values(by="Votes", ascending=False)
            df.index += 1  # Rank starting from 1
            df.to_excel(writer, sheet_name=portfolio.name[:31], index_label="Rank")

    writer.close()
    output.seek(0)
    return send_file(output, download_name="Election_Results.xlsx", as_attachment=True)


# ---------------- VOTER SIDE ----------------
@app.route("/voter/dashboard")
def voter_dashboard():
    if "voter_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    # Allow access when either the device is authenticated for this session
    # OR the public kiosk is open (admin authenticated the device for the kiosk)
    election = Election.query.first()
    kiosk_open = election.device_open if election else False
    if not (is_device_authenticated() or kiosk_open):
        flash("Please enter the device password first", "warning")
        return redirect(url_for("voter_device_check"))

    voter = User.query.get(session["voter_id"])

    # Already voted check
    if voter.voted:
        flash("You have already voted", "info")
        # only remove voter session data, keep device authentication so next voter doesn't need to re-authenticate
        session.pop('voter_id', None)
        return redirect(url_for("public_voter_login"))

    portfolios = Portfolio.query.all()
    return render_template("voter_dashboard.html", portfolios=portfolios)


@app.route("/voter/submit", methods=["POST"])
def submit_vote():
    if "voter_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    voter = User.query.get(session["voter_id"])

    # Loop through form data to get selected candidates
    for key, value in request.form.items():
        if key.startswith("portfolio_"):  # e.g., portfolio_1 = candidate_id
            candidate_id = int(value)
            vote = Vote(voter_id=voter.id, candidate_id=candidate_id)
            db.session.add(vote)

    # Mark voter as voted
    voter.voted = True
    db.session.commit()
    flash("Your vote has been submitted successfully!", "success")
    # only remove voter session data; keep device authentication active so the next voter can vote without re-authenticating
    session.pop('voter_id', None)
    # After voting at a kiosk, return to the kiosk login so the next voter can enter their index number
    return redirect(url_for("public_voter_login"))


@app.route("/voter/device", methods=["GET", "POST"])
def voter_device_check():
    if "voter_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    election = Election.query.first()
    if not election or not election.is_active:
        flash("Election is not active", "warning")
        return redirect(url_for("login"))

    # If device is already authenticated and password still matches current election, skip password
    if is_device_authenticated():
        return redirect(url_for("voter_dashboard"))

    if request.method == "POST":
        device_password = request.form.get("device_password")
        if device_password == election.device_password:
            session["device_authenticated"] = True  # mark device as authenticated
            session["device_password_hash"] = hashlib.sha256(str(device_password).encode()).hexdigest()
            flash("Device authenticated successfully!", "success")
            return redirect(url_for("voter_dashboard"))
        else:
            flash("Wrong device password", "danger")

    return render_template("voter_device.html")


# ---------------- ADMIN: STUDENT CLASSES ----------------
@app.route("/admin/student_classes", methods=["GET", "POST"])
def student_classes():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        year = request.form.get("year")
        name = request.form.get("name")  # class name e.g., "Form 1A"

        if not year or not name:
            flash("Both year and class name are required", "danger")
            return redirect(url_for("student_classes"))

        # Check if class for this year already exists
        existing = Class.query.filter_by(name=name, year=year).first()
        if existing:
            flash("This class already exists", "warning")
            return redirect(url_for("student_classes"))

        new_class = Class(name=name, year=int(year))
        db.session.add(new_class)
        db.session.commit()
        flash(f"Class {name} for year {year} added successfully", "success")
        return redirect(url_for("student_classes"))

    classes = Class.query.order_by(Class.year, Class.name).all()
    return render_template("student_class.html", classes=classes)


# ---------------- PORTFOLIOS ----------------
@app.route("/admin/portfolios", methods=["GET", "POST"])
def portfolios():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("name")
        if name:
            db.session.add(Portfolio(name=name))
            db.session.commit()
            flash("Portfolio added successfully", "success")
        else:
            flash("Portfolio name cannot be empty", "danger")
        return redirect(url_for("portfolios"))

    portfolios = Portfolio.query.all()
    return render_template("portfolios.html", portfolios=portfolios)


# ---------------- ELECTION ----------------
@app.route("/admin/election", methods=["GET", "POST"])
def election():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    e = Election.query.first()
    if request.method == "POST":
        if not e:
            e = Election()
            db.session.add(e)

        start_time = request.form.get("start_time")
        end_time = request.form.get("end_time")
        device_password = request.form.get("device_password")
        is_active = True if request.form.get("is_active") else False

        e.start_time = datetime.fromisoformat(start_time) if start_time else None
        e.end_time = datetime.fromisoformat(end_time) if end_time else None
        old_password = e.device_password
        e.device_password = device_password
        e.is_active = is_active

        db.session.commit()

        # If device password changed, invalidate server-side sessions (if available)
        password_changed = (old_password != device_password)
        if password_changed:
            if HAS_FLASK_SESSION:
                clear_all_sessions(keep_admin=True)
                flash("Election settings updated and active sessions cleared (device password change)", "success")
            else:
                # Even without Flask-Session, device auth will be invalidated because we compare stored hashes
                flash("Election settings updated (device password changed). Active device sessions have been invalidated.", "success")
        else:
            flash("Election settings updated", "success")
        return redirect(url_for("election"))

    return render_template("election.html", election=e)


# ---------------- VOTER KIOSK (admin can open/close) ----------------
@app.route('/admin/voter_kiosk', methods=['GET', 'POST'])
def admin_voter_kiosk():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    e = Election.query.first()
    if not e:
        e = Election()
        db.session.add(e)
        db.session.commit()

    if request.method == 'POST':
        # Accept either form-encoded or JSON (AJAX) submissions
        action = request.form.get('action')
        device_password = request.form.get('device_password')
        if request.is_json:
            data = request.get_json() or {}
            action = data.get('action') or action
            device_password = data.get('device_password') or device_password

        msg = None
        success = False
        if action == 'open':
            if device_password == e.device_password:
                e.device_open = True
                db.session.commit()
                msg = 'Voter kiosk opened. Voters can now log in at /vote'
                success = True
            else:
                msg = 'Wrong device password'
                success = False
        elif action == 'close':
            e.device_open = False
            db.session.commit()
            msg = 'Voter kiosk closed'
            success = True

        # Return JSON for AJAX requests
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': success, 'message': msg, 'device_open': e.device_open})

        flash(msg, 'success' if success else 'danger')
        return redirect(url_for('admin_voter_kiosk'))

    return render_template('admin_voter_kiosk.html', election=e)

@app.route("/students/export")
def export_students():
    # You can restrict to admin if you want:
    # if session.get("role") != "admin":
    #     return redirect(url_for("login"))

    # Export all non-deleted voters (students)
    students = (
        User.query.filter_by(role="voter", is_deleted=False)
        .order_by(User.index_number)
        .all()
    )

    data = []
    for s in students:
        data.append(
            {
                "Index Number": s.index_number,
                "Name": s.name,
                "Class": s.classroom.name if s.classroom else "N/A",
            }
        )

    if not data:
        # still provide headers even if empty
        data.append({"Index Number": "", "Name": "", "Class": ""})

    df = pd.DataFrame(data)

    output = BytesIO()
    try:
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Students")
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name="students_list.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception:
        # fallback to CSV if Excel engine not available
        output = BytesIO()
        df.to_csv(output, index=False)
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name="students_list.csv",
            mimetype="text/csv",
        )
# Page shown to admin immediately after login, allowing them to choose to open the kiosk or go to dashboard
@app.route('/admin/after_login')
def admin_after_login():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    e = Election.query.first()
    return render_template('admin_after_login.html', election=e)


# ---------------- PUBLIC VOTER LOGIN (kiosk) ----------------
@app.route('/vote', methods=['GET', 'POST'])
def public_voter_login():
    e = Election.query.first()
    if not e or not e.is_active:
        flash('Election is not active', 'warning')
        return redirect(url_for('login'))

    if not e.device_open:
        flash('Voting kiosk is closed. Please wait for an administrator to open it.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        index = request.form.get('index_number')
        if not index:
            flash('Please enter your index number', 'warning')
            return redirect(url_for('public_voter_login'))
        voter = User.query.filter_by(index_number=index, role='voter', is_deleted=False).first()
        if not voter:
            flash('Voter not found', 'danger')
            return redirect(url_for('public_voter_login'))
        if voter.voted:
            flash('You have already voted', 'info')
            return redirect(url_for('public_voter_login'))
        # set voter in session and proceed to dashboard
        session['voter_id'] = voter.id
        return redirect(url_for('voter_dashboard'))

    return render_template('voter_kiosk_login.html')


# ---------------- NOW SERVING (public) ----------------
@app.route('/now_serving')
def now_serving():
    # Public display showing counts and last served voter
    total = User.query.filter_by(role='voter', is_deleted=False).count()
    voted = User.query.filter_by(role='voter', is_deleted=False, voted=True).count()
    remaining = total - voted
    last_vote = Vote.query.order_by(Vote.timestamp.desc()).first()
    last_voter = None
    if last_vote:
        voter = User.query.get(last_vote.voter_id)
        if voter:
            last_voter = {'index': voter.index_number, 'name': voter.name}

    return render_template('now_serving.html', total=total, voted=voted, remaining=remaining, last_voter=last_voter)


@app.route('/now_serving/status')
def now_serving_status():
    total = User.query.filter_by(role='voter', is_deleted=False).count()
    voted = User.query.filter_by(role='voter', is_deleted=False, voted=True).count()
    remaining = total - voted
    last_vote = Vote.query.order_by(Vote.timestamp.desc()).first()
    last_voter = None
    if last_vote:
        voter = User.query.get(last_vote.voter_id)
        if voter:
            last_voter = {'index': voter.index_number, 'name': voter.name}

    return jsonify({'total': total, 'voted': voted, 'remaining': remaining, 'last_voter': last_voter})


# ---------------- APP STARTUP & DB MIGRATION ----------------
if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    with app.app_context():
        db.create_all()

        # Ensure is_deleted columns exist (adds column for SQLite if missing)
        # Use a transaction so DDL is executed reliably and errors are visible
        try:
            with db.engine.begin() as conn:
                # users
                res = conn.execute(text("PRAGMA table_info('user')")).fetchall()
                user_cols = [r[1] for r in res]
                if "is_deleted" not in user_cols:
                    print("Adding is_deleted column to user table")
                    conn.execute(
                        text("ALTER TABLE user ADD COLUMN is_deleted INTEGER DEFAULT 0")
                    )

                # candidates
                res = conn.execute(text("PRAGMA table_info('candidate')")).fetchall()
                cand_cols = [r[1] for r in res]
                if "is_deleted" not in cand_cols:
                    print("Adding is_deleted column to candidate table")
                    conn.execute(
                        text(
                            "ALTER TABLE candidate ADD COLUMN is_deleted INTEGER DEFAULT 0"
                        )
                    )
                # candidate photo column
                if "photo" not in cand_cols:
                    print("Adding photo column to candidate table")
                    conn.execute(
                        text("ALTER TABLE candidate ADD COLUMN photo VARCHAR(255)")
                    )

                # election: device_open column (controls public kiosk)
                res = conn.execute(text("PRAGMA table_info('election')")).fetchall()
                election_cols = [r[1] for r in res]
                if "device_open" not in election_cols:
                    print("Adding device_open column to election table")
                    conn.execute(
                        text("ALTER TABLE election ADD COLUMN device_open INTEGER DEFAULT 0")
                    )
        except Exception as e:
            # Surface migration errors to the console so we can debug them
            print("Error while ensuring is_deleted columns:", e)
            # re-raise so startup fails loudly and you can see the cause
            raise

        # create default admin
        if not User.query.filter_by(index_number="admin").first():
            db.session.add(
                User(
                    index_number="admin",
                    name="Danny Dravie",
                    password="12345",
                    role="admin",
                )
            )
        # create default voter
        if not User.query.filter_by(index_number="230001").first():
            db.session.add(
                User(
                    index_number="230001",
                    name="Daniel Dravie",
                    sex="Male",
                    role="voter",
                    class_id=None,
                )
            )
        db.session.commit()

    app.run(debug=True)

