# SecureTrack

SecureTrack is a Flask-based cybersecurity incident and vulnerability management prototype. It separates presentation (Jinja/HTML/CSS), application/business logic (Flask/Python), and data persistence (SQLAlchemy with SQLite locally or PostgreSQL in deployment).

## Features

- Registration, login and logout with hashed passwords
- Admin and Analyst roles
- Incident and vulnerability tracking
- Automatic risk score (`likelihood × impact`) and severity classification
- Search and filtering
- Remediation notes and ownership
- Dashboard statistics
- Audit/activity log
- Server-side validation

## Run locally

```powershell
python -m venv venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. The first registered account becomes the prototype Admin account.

Local development uses SQLite automatically and stores the database under Flask's `instance` directory.

## Deployment configuration

The project is prepared for a hosted Python service - Render:

- `gunicorn` is included as the production WSGI server.
- `DATABASE_URL` switches persistence from local SQLite to a hosted PostgreSQL database.
- `SECRET_KEY` is read from the hosting environment rather than committed to source control.
- `/health` provides a simple health-check endpoint.
- Proxy headers are handled for HTTPS hosting.
- `render.yaml` describes the web service and PostgreSQL database.


## Demonstration / test data

```bash
python seed_demo_data.py
```

The seed script adds realistic fictional incidents and vulnerabilities, including Open, In Progress and Resolved records across Low, Medium, High and Critical severities. Vulnerability risk scores are generated through SecureTrack's existing `calculate_risk()` business logic rather than being hard-coded.

The script will not add records when incident or vulnerability data already exists, which prevents accidental duplicate datasets. All seeded records are fictional and are intended only for demonstration and testing.

## Expanded incident and vulnerability records

Incidents now include a generated incident reference, occurrence timestamp, system-raised timestamp, category, impacted area/estate, affected assets, detection source, business impact, immediate containment/actions, responsible team, owner, and the username/full name of the person who raised the record.

Vulnerabilities now include a generated vulnerability reference, CVE number (or N/A for non-CVE/internal findings), impacted area/estate, affected assets, discovery source, responsible team, remediation due date, risk scoring, system-raised timestamp, and the username/full name of the person who raised the record.

Registration requires first name, last name and username so records have meaningful attribution.


## Seeded demonstration users
Running `python seed_demo_data.py` creates fictional users for assignment/demo testing as well as the sample security records:

- `admin` — System Administrator — Admin
- `joe.bloggs` — Joe Bloggs — Analyst
- `steven.frypan` — Steven Frypan — Analyst
- `natalie.airpod` — Natalie Airpod — Analyst
- `priya.shah` — Priya Shah — Analyst
- `marcus.green` — Marcus Green — Analyst

All seeded demo accounts use the development-only password `SecureTrackDemo123!`. For real-world use, this would be changed. The assignment dropdowns are populated dynamically from the `User` table rather than from a hard-coded list.

## Seeded demonstration users
`python seed_demo_data.py` creates fictional users as well as sample security records:
- `admin` — System Administrator — Admin
- `joe.bloggs` — Joe Bloggs — Analyst
- `steven.frypan` — Steven Frypan — Analyst
- `natalie.airpod` — Natalie Airpod — Analyst
- `priya.shah` — Priya Shah — Analyst
- `marcus.green` — Marcus Green — Analyst

All seeded demo accounts use the development-only password `SecureTrackDemo123!`. The assignment dropdowns are populated dynamically from the User database table.
