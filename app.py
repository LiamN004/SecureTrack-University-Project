import os
from datetime import datetime
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

database_url = os.environ.get("DATABASE_URL", "sqlite:///securetrack.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-before-deployment")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="Analyst")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_number = db.Column(db.String(30), unique=True, nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False, default="Other")
    occurred_at = db.Column(db.DateTime, nullable=False)
    raised_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    impacted_area = db.Column(db.String(150), nullable=False, default="Not specified")
    affected_assets = db.Column(db.String(255), nullable=False, default="")
    detection_source = db.Column(db.String(100), nullable=False, default="")
    business_impact = db.Column(db.Text, nullable=False, default="")
    immediate_actions = db.Column(db.Text, nullable=False, default="")
    responsible_team = db.Column(db.String(100), nullable=False, default="Unassigned")
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Open")
    owner = db.Column(db.String(80), nullable=False, default="Unassigned")
    raised_by_username = db.Column(db.String(80), nullable=False)
    raised_by_name = db.Column(db.String(170), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vulnerability_number = db.Column(db.String(30), unique=True, nullable=False)
    cve_number = db.Column(db.String(30), nullable=False, default="N/A")
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    impacted_area = db.Column(db.String(150), nullable=False, default="Not specified")
    affected_assets = db.Column(db.String(255), nullable=False, default="")
    source = db.Column(db.String(100), nullable=False, default="")
    responsible_team = db.Column(db.String(100), nullable=False, default="Unassigned")
    remediation_due = db.Column(db.Date, nullable=True)
    likelihood = db.Column(db.Integer, nullable=False)
    impact = db.Column(db.Integer, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Open")
    owner = db.Column(db.String(80), nullable=False, default="Unassigned")
    remediation = db.Column(db.Text, nullable=False, default="")
    raised_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    raised_by_username = db.Column(db.String(80), nullable=False)
    raised_by_name = db.Column(db.String(170), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class RecordComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_type = db.Column(db.String(30), nullable=False, index=True)
    record_id = db.Column(db.Integer, nullable=False, index=True)
    update_type = db.Column(db.String(30), nullable=False, default="Update")
    comment = db.Column(db.Text, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    author_name = db.Column(db.String(170), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    record_type = db.Column(db.String(40), nullable=False)
    record_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def audit(action, record_type, record_id=None, details=""):
    username = current_user.username if current_user.is_authenticated else "System"
    db.session.add(AuditLog(username=username, action=action, record_type=record_type,
                            record_id=record_id, details=details[:255]))


def calculate_risk(likelihood, impact):
    score = likelihood * impact
    if score >= 20:
        severity = "Critical"
    elif score >= 12:
        severity = "High"
    elif score >= 6:
        severity = "Medium"
    else:
        severity = "Low"
    return score, severity


def next_reference(model, prefix):
    year = datetime.utcnow().year
    latest = model.query.order_by(model.id.desc()).first()
    sequence = (latest.id + 1) if latest else 1
    return f"{prefix}-{year}-{sequence:04d}"


def parse_datetime_local(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M")
    except (TypeError, ValueError):
        return None


def parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "Admin":
            flash("Administrator access is required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def assignment_users():
    return User.query.order_by(User.first_name.asc(), User.last_name.asc(), User.username.asc()).all()


def valid_assignee(username):
    return username == "Unassigned" or User.query.filter_by(username=username).first() is not None


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
        elif not first_name or not last_name:
            flash("First name and last name are required.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("That username already exists.", "danger")
        else:
            role = "Admin" if User.query.count() == 0 else "Analyst"
            user = User(username=username, first_name=first_name, last_name=last_name, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash(f"Account created. Role: {role}.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            audit("Login", "User", user.id, "Successful login")
            db.session.commit()
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    audit("Logout", "User", current_user.id, "User logged out")
    db.session.commit()
    logout_user()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}, 200


@app.route("/")
@login_required
def dashboard():
    open_incidents = Incident.query.filter(Incident.status != "Resolved").count()
    vulnerabilities = Vulnerability.query.count()
    critical_issues = Incident.query.filter_by(severity="Critical").count() + Vulnerability.query.filter_by(severity="Critical").count()
    resolved_issues = Incident.query.filter_by(status="Resolved").count() + Vulnerability.query.filter_by(status="Resolved").count()
    recent_incidents = Incident.query.order_by(Incident.created_at.desc()).limit(5).all()
    recent_vulnerabilities = Vulnerability.query.order_by(Vulnerability.created_at.desc()).limit(5).all()
    recent = ([{"id": x.id, "reference": x.incident_number, "title": x.title, "kind": "Incident", "severity": x.severity, "status": x.status, "created_at": x.created_at, "detail_endpoint": "incident_detail"} for x in recent_incidents] +
              [{"id": x.id, "reference": x.vulnerability_number, "title": x.title, "kind": "Vulnerability", "severity": x.severity, "status": x.status, "created_at": x.created_at, "detail_endpoint": "vulnerability_detail"} for x in recent_vulnerabilities])
    recent.sort(key=lambda x: x["created_at"], reverse=True)
    return render_template("dashboard.html", open_incidents=open_incidents, critical_issues=critical_issues,
                           vulnerabilities=vulnerabilities, resolved_issues=resolved_issues, recent=recent[:8])


@app.route("/incidents")
@login_required
def incidents():
    q = request.args.get("q", "").strip()
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")
    query = Incident.query
    if q:
        query = query.filter((Incident.incident_number.ilike(f"%{q}%")) | (Incident.title.ilike(f"%{q}%")) |
                             (Incident.description.ilike(f"%{q}%")) | (Incident.impacted_area.ilike(f"%{q}%")))
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    return render_template("incidents.html", incidents=query.order_by(Incident.raised_at.desc()).all())


@app.route("/incidents/new", methods=["GET", "POST"])
@login_required
def new_incident():
    reference = next_reference(Incident, "INC")
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "Other")
        occurred_at = parse_datetime_local(request.form.get("occurred_at"))
        impacted_area = request.form.get("impacted_area", "").strip()
        affected_assets = request.form.get("affected_assets", "").strip()
        detection_source = request.form.get("detection_source", "").strip()
        business_impact = request.form.get("business_impact", "").strip()
        immediate_actions = request.form.get("immediate_actions", "").strip()
        responsible_team = request.form.get("responsible_team", "").strip() or "Unassigned"
        severity = request.form.get("severity", "")
        owner = request.form.get("owner", "").strip() or "Unassigned"
        if not title or not description or not occurred_at or not impacted_area or severity not in {"Low", "Medium", "High", "Critical"} or not valid_assignee(owner):
            flash("Complete all required incident fields.", "danger")
        else:
            item = Incident(incident_number=reference, title=title, description=description, category=category,
                            occurred_at=occurred_at, raised_at=datetime.utcnow(), impacted_area=impacted_area,
                            affected_assets=affected_assets, detection_source=detection_source,
                            business_impact=business_impact, immediate_actions=immediate_actions,
                            responsible_team=responsible_team, severity=severity, owner=owner,
                            raised_by_username=current_user.username, raised_by_name=current_user.full_name)
            db.session.add(item)
            db.session.flush()
            audit("Created", "Incident", item.id, f"{reference}: {title}")
            db.session.commit()
            flash(f"Incident {reference} recorded successfully.", "success")
            return redirect(url_for("incidents"))
    return render_template("incident_form.html", incident=None, reference=reference, users=assignment_users())


@app.route("/incidents/<int:item_id>")
@login_required
def incident_detail(item_id):
    item = db.get_or_404(Incident, item_id)
    comments = RecordComment.query.filter_by(record_type="Incident", record_id=item.id).order_by(RecordComment.created_at.desc()).all()
    return render_template("incident_detail.html", incident=item, comments=comments)


@app.post("/incidents/<int:item_id>/comments")
@login_required
def add_incident_comment(item_id):
    item = db.get_or_404(Incident, item_id)
    update_type = request.form.get("update_type", "Update").strip()
    comment_text = request.form.get("comment", "").strip()
    allowed_types = {"Update", "Investigation", "Remediation", "Containment", "Resolution"}
    if update_type not in allowed_types:
        update_type = "Update"
    if not comment_text:
        flash("Enter an update before submitting.", "danger")
    elif len(comment_text) > 4000:
        flash("Update must be 4,000 characters or fewer.", "danger")
    else:
        comment = RecordComment(record_type="Incident", record_id=item.id, update_type=update_type,
                                comment=comment_text, username=current_user.username, author_name=current_user.full_name)
        db.session.add(comment)
        audit("Comment added", "Incident", item.id, f"{item.incident_number}: {update_type}")
        db.session.commit()
        flash("Incident tracking update added.", "success")
    return redirect(url_for("incident_detail", item_id=item.id))


@app.route("/incidents/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
def edit_incident(item_id):
    item = db.get_or_404(Incident, item_id)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "Other")
        occurred_at = parse_datetime_local(request.form.get("occurred_at"))
        impacted_area = request.form.get("impacted_area", "").strip()
        affected_assets = request.form.get("affected_assets", "").strip()
        detection_source = request.form.get("detection_source", "").strip()
        business_impact = request.form.get("business_impact", "").strip()
        immediate_actions = request.form.get("immediate_actions", "").strip()
        responsible_team = request.form.get("responsible_team", "").strip() or "Unassigned"
        severity = request.form.get("severity", "")
        status = request.form.get("status", "")
        owner = request.form.get("owner", "").strip() or "Unassigned"
        if not title or not description or not occurred_at or not impacted_area or severity not in {"Low", "Medium", "High", "Critical"} or status not in {"Open", "In Progress", "Resolved"} or not valid_assignee(owner):
            flash("Check the incident fields and try again.", "danger")
        else:
            item.title, item.description, item.category, item.occurred_at = title, description, category, occurred_at
            item.impacted_area, item.affected_assets, item.detection_source = impacted_area, affected_assets, detection_source
            item.business_impact, item.immediate_actions, item.responsible_team = business_impact, immediate_actions, responsible_team
            item.severity, item.status, item.owner = severity, status, owner
            audit("Updated", "Incident", item.id, f"{item.incident_number}: {title}")
            db.session.commit()
            flash("Incident updated.", "success")
            return redirect(url_for("incidents"))
    return render_template("incident_form.html", incident=item, reference=item.incident_number, users=assignment_users())


@app.post("/incidents/<int:item_id>/delete")
@login_required
@admin_required
def delete_incident(item_id):
    item = db.get_or_404(Incident, item_id)
    audit("Deleted", "Incident", item.id, f"{item.incident_number}: {item.title}")
    db.session.delete(item)
    db.session.commit()
    flash("Incident deleted.", "success")
    return redirect(url_for("incidents"))


@app.route("/vulnerabilities")
@login_required
def vulnerabilities():
    q = request.args.get("q", "").strip()
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")
    query = Vulnerability.query
    if q:
        query = query.filter((Vulnerability.vulnerability_number.ilike(f"%{q}%")) | (Vulnerability.cve_number.ilike(f"%{q}%")) |
                             (Vulnerability.title.ilike(f"%{q}%")) | (Vulnerability.description.ilike(f"%{q}%")) |
                             (Vulnerability.impacted_area.ilike(f"%{q}%")))
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    return render_template("vulnerabilities.html", vulnerabilities=query.order_by(Vulnerability.raised_at.desc()).all())


@app.route("/vulnerabilities/new", methods=["GET", "POST"])
@login_required
def new_vulnerability():
    reference = next_reference(Vulnerability, "VUL")
    if request.method == "POST":
        cve_number = request.form.get("cve_number", "").strip().upper() or "N/A"
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        impacted_area = request.form.get("impacted_area", "").strip()
        affected_assets = request.form.get("affected_assets", "").strip()
        source = request.form.get("source", "").strip()
        responsible_team = request.form.get("responsible_team", "").strip() or "Unassigned"
        owner = request.form.get("owner", "").strip() or "Unassigned"
        remediation = request.form.get("remediation", "").strip()
        remediation_due = parse_date(request.form.get("remediation_due"))
        try:
            likelihood = int(request.form.get("likelihood", 0))
            impact = int(request.form.get("impact", 0))
        except ValueError:
            likelihood = impact = 0
        if not title or not description or not impacted_area or likelihood not in range(1, 6) or impact not in range(1, 6) or not valid_assignee(owner):
            flash("Complete all required fields; likelihood and impact must be 1-5.", "danger")
        else:
            score, severity = calculate_risk(likelihood, impact)
            item = Vulnerability(vulnerability_number=reference, cve_number=cve_number, title=title,
                                 description=description, impacted_area=impacted_area, affected_assets=affected_assets,
                                 source=source, responsible_team=responsible_team, remediation_due=remediation_due,
                                 likelihood=likelihood, impact=impact, risk_score=score, severity=severity,
                                 owner=owner, remediation=remediation, raised_at=datetime.utcnow(),
                                 raised_by_username=current_user.username, raised_by_name=current_user.full_name)
            db.session.add(item)
            db.session.flush()
            audit("Created", "Vulnerability", item.id, f"{reference} / {cve_number}; risk {score} ({severity})")
            db.session.commit()
            flash(f"Vulnerability {reference} saved. Risk score: {score} ({severity}).", "success")
            return redirect(url_for("vulnerabilities"))
    return render_template("vulnerability_form.html", vulnerability=None, reference=reference, users=assignment_users())


@app.route("/vulnerabilities/<int:item_id>")
@login_required
def vulnerability_detail(item_id):
    item = db.get_or_404(Vulnerability, item_id)
    comments = RecordComment.query.filter_by(record_type="Vulnerability", record_id=item.id).order_by(RecordComment.created_at.desc()).all()
    return render_template("vulnerability_detail.html", vulnerability=item, comments=comments)


@app.post("/vulnerabilities/<int:item_id>/comments")
@login_required
def add_vulnerability_comment(item_id):
    item = db.get_or_404(Vulnerability, item_id)
    update_type = request.form.get("update_type", "Update").strip()
    comment_text = request.form.get("comment", "").strip()
    allowed_types = {"Update", "Investigation", "Remediation", "Mitigation", "Resolution"}
    if update_type not in allowed_types:
        update_type = "Update"
    if not comment_text:
        flash("Enter an update before submitting.", "danger")
    elif len(comment_text) > 4000:
        flash("Update must be 4,000 characters or fewer.", "danger")
    else:
        comment = RecordComment(record_type="Vulnerability", record_id=item.id, update_type=update_type,
                                comment=comment_text, username=current_user.username, author_name=current_user.full_name)
        db.session.add(comment)
        audit("Comment added", "Vulnerability", item.id, f"{item.vulnerability_number}: {update_type}")
        db.session.commit()
        flash("Vulnerability tracking update added.", "success")
    return redirect(url_for("vulnerability_detail", item_id=item.id))


@app.route("/vulnerabilities/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
def edit_vulnerability(item_id):
    item = db.get_or_404(Vulnerability, item_id)
    if request.method == "POST":
        cve_number = request.form.get("cve_number", "").strip().upper() or "N/A"
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        impacted_area = request.form.get("impacted_area", "").strip()
        affected_assets = request.form.get("affected_assets", "").strip()
        source = request.form.get("source", "").strip()
        responsible_team = request.form.get("responsible_team", "").strip() or "Unassigned"
        owner = request.form.get("owner", "").strip() or "Unassigned"
        remediation = request.form.get("remediation", "").strip()
        remediation_due = parse_date(request.form.get("remediation_due"))
        status = request.form.get("status", "")
        try:
            likelihood = int(request.form.get("likelihood", 0))
            impact = int(request.form.get("impact", 0))
        except ValueError:
            likelihood = impact = 0
        if not title or not description or not impacted_area or likelihood not in range(1, 6) or impact not in range(1, 6) or status not in {"Open", "In Progress", "Resolved"} or not valid_assignee(owner):
            flash("Check the vulnerability fields and try again.", "danger")
        else:
            score, severity = calculate_risk(likelihood, impact)
            item.cve_number, item.title, item.description = cve_number, title, description
            item.impacted_area, item.affected_assets, item.source = impacted_area, affected_assets, source
            item.responsible_team, item.remediation_due = responsible_team, remediation_due
            item.owner, item.remediation = owner, remediation
            item.likelihood, item.impact, item.risk_score, item.severity, item.status = likelihood, impact, score, severity, status
            audit("Updated", "Vulnerability", item.id, f"{item.vulnerability_number} / {cve_number}; risk {score} ({severity})")
            db.session.commit()
            flash("Vulnerability updated.", "success")
            return redirect(url_for("vulnerabilities"))
    return render_template("vulnerability_form.html", vulnerability=item, reference=item.vulnerability_number, users=assignment_users())


@app.post("/vulnerabilities/<int:item_id>/delete")
@login_required
@admin_required
def delete_vulnerability(item_id):
    item = db.get_or_404(Vulnerability, item_id)
    audit("Deleted", "Vulnerability", item.id, f"{item.vulnerability_number}: {item.title}")
    db.session.delete(item)
    db.session.commit()
    flash("Vulnerability deleted.", "success")
    return redirect(url_for("vulnerabilities"))


@app.route("/activity")
@login_required
def activity():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template("activity.html", logs=logs)


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
