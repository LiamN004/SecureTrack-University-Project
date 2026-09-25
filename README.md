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

## Accessing the Deployed Application

SecureTrack has been deployed as a live web application, allowing the completed system to be accessed and tested through a standard web browser without requiring any local installation or development software. The application is hosted using Render and uses a deployed PostgreSQL database for persistent data storage, demonstrating the distributed architecture described within this report. The live deployment can be accessed at: 
WEBSITE URL --> PLEASE SEE LINK PROVIDED IN THE ASSIGNMENT BRIEF.

As SecureTrack is hosted using Render's free service plan, the application may enter an inactive state when it has not been accessed for a period of time. Therefore, when the deployment link is first opened, the website may take a couple of minutes to become available while the hosted service starts. If the page does not immediately load, please allow a short period for the service to initialise before refreshing the page. Once running, the application can be used normally to test the implemented functionality, including authentication, incident and vulnerability management, assignment, risk scoring, remediation tracking, filtering and activity history. Account login details for the website are listed below. 

## Run locally

An offline backup version of SecureTrack is also available as a contingency should the live hosted deployment be temporarily unavailable. The offline package can be downloaded from:
GOOGLE DRIVE LINK –-> PLEASE SEE LINK PROVIDED IN THE ASSIGNMENT BRIEF.

Full instructions explaining how to launch and access the local version of SecureTrack are included within the download.

The offline version is provided solely as a backup method of accessing and demonstrating the application. The recommended and primary method of accessing SecureTrack is through the live website deployment, as this represents the intended distributed implementation of the system and demonstrates the deployed web application and database architecture described throughout this report.

## Deployment configuration

The project is prepared and used on a hosted Python service - Render:

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

On the live deployment, this script has already been ran and "test" data is present within the website.

## Expanded incident and vulnerability records

Incidents include a generated incident reference, occurrence timestamp, system-raised timestamp, category, impacted area/estate, affected assets, detection source, business impact, immediate containment/actions, responsible team, owner, and the username/full name of the person who raised the record.

Vulnerabilities include a generated vulnerability reference, CVE number (or N/A for non-CVE/internal findings), impacted area/estate, affected assets, discovery source, responsible team, remediation due date, risk scoring, system-raised timestamp, and the username/full name of the person who raised the record.

Registration requires first name, last name and username so records have meaningful attribution. Please see demonstration uses below.


## Seeded demonstration users
Running `python seed_demo_data.py` creates fictional users for assignment/demo testing as well as the sample security records:

- `admin` — System Administrator — Admin
- `joe.bloggs` — Joe Bloggs — Analyst
- `steven.frypan` — Steven Frypan — Analyst
- `natalie.airpod` — Natalie Airpod — Analyst
- `priya.shah` — Priya Shah — Analyst
- `marcus.green` — Marcus Green — Analyst

All seeded demo accounts use the development-only password `SecureTrackDemo123!`. For real-world use, this would be changed. The assignment dropdowns are populated dynamically from the `User` table rather than from a hard-coded list.

The username for the accounts is the first item provided in the list above:

Ie: The admin accounts username is 'Admin'. Joe Bloggs' username is 'joe.bloggs'. All accounts share the same password for demonstrative purposes only: `SecureTrackDemo123!`
