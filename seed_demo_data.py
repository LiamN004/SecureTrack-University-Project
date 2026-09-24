"""Populate SecureTrack with fictional demonstration records.

Run once with: python seed_demo_data.py
Use a fresh database. The script exits if security records already exist.
"""
from datetime import datetime, timedelta
from app import app, db, User, Incident, Vulnerability, AuditLog, calculate_risk


def dt(days_ago, hours=0):
    return datetime.utcnow() - timedelta(days=days_ago, hours=hours)


INCIDENTS = [
    ("Suspicious Administrator Login", "Multiple successful administrator logins were observed from an unusual source IP outside normal working hours.", "Unauthorised Access", "Critical", "Open", "SOC Team", "Corporate identity estate", "Domain controller / privileged account", "SIEM", "Potential privileged account compromise requiring urgent validation.", "Source IP blocked and account sessions reviewed.", 0, 2),
    ("Ransomware Detection on WS-014", "Endpoint protection detected ransomware-like file encryption behaviour on workstation WS-014.", "Malware", "Critical", "In Progress", "Incident Response", "Corporate endpoint estate", "WS-014", "EDR", "Potential loss of endpoint availability and risk of lateral movement.", "Device isolated from the network and forensic triage started.", 1, 3),
    ("Repeated Failed Login Attempts", "A user account generated a high volume of failed authentication attempts within a short period.", "Suspicious Activity", "High", "Open", "SOC Team", "Identity and access management", "User authentication service", "SIEM", "Possible password attack against a user account.", "Account and source IP reviewed; monitoring increased.", 2, 1),
    ("Malware Alert on Finance Laptop", "Endpoint security detected and quarantined a suspicious executable on a Finance department laptop.", "Malware", "High", "In Progress", "Endpoint Team", "Finance", "FIN-LT-022", "EDR", "Potential impact to a finance user and sensitive business data.", "File quarantined and full endpoint scan initiated.", 3, 4),
    ("Phishing Email Reported", "A staff member reported a credential-harvesting email impersonating an internal password-expiry notification.", "Phishing", "Medium", "Resolved", "SOC Team", "Corporate email", "Microsoft 365 mailboxes", "User report", "Risk of credential theft if recipients interact with the link.", "Message removed and sender/domain indicators blocked.", 5, 2),
    ("Unusual Outbound Network Traffic", "Monitoring identified an internal host making repeated outbound connections to an uncommon external destination.", "Suspicious Activity", "High", "Open", "Network Security", "Corporate network", "APP-SRV-03", "Network monitoring", "Potential command-and-control traffic requiring investigation.", "Destination blocked pending investigation.", 6, 5),
    ("Unauthorised USB Device", "A removable storage device was connected to a managed workstation contrary to local security policy.", "Policy Violation", "Low", "Resolved", "Desktop Support", "Corporate endpoint estate", "HR-WS-008", "Endpoint control", "Limited operational impact; policy and data handling concern.", "Device removed and user reminded of removable-media policy.", 9, 1),
]

VULNERABILITIES = [
    ("CVE-2026-41001", "Exposed Administrative Interface", "An administrative management interface is reachable from an untrusted network segment.", 5, 5, "Open", "Network Security", "Perimeter / management network", "Management gateway", "Vulnerability scan", "Restrict the interface to the management network and require authenticated VPN access.", 0, 5),
    ("CVE-2026-31872", "Missing Critical Security Patches", "A server is missing security updates addressing known high-impact vulnerabilities.", 5, 4, "In Progress", "Infrastructure Team", "Windows server estate", "SRV-APP-07", "Patch compliance scan", "Test and deploy the outstanding security updates during the approved maintenance window.", 1, 6),
    ("CVE-2026-27544", "Outdated Apache Web Server", "The public web server is running an outdated Apache release that is outside the organisation's patch baseline.", 4, 4, "Open", "Web Team", "DMZ / public web estate", "WEB-01", "Vulnerability scan", "Upgrade Apache to a supported release and retest the hosted application.", 2, 7),
    ("N/A", "Unsupported Operating System", "A legacy endpoint is running an operating system that no longer receives routine security updates.", 4, 3, "Open", "Desktop Support", "Legacy endpoint estate", "LEGACY-WS-04", "Asset review", "Migrate the endpoint to a supported operating system or remove it from service.", 4, 3),
    ("N/A", "Weak Password Policy", "The current application password policy permits passwords below the organisation's preferred minimum standard.", 3, 3, "Open", "IAM Team", "Internal application estate", "HR application", "Configuration review", "Increase the minimum password requirements and review authentication controls.", 5, 4),
    ("CVE-2026-19420", "TLS Configuration Weakness", "A service permits legacy TLS configuration that does not meet the current security baseline.", 2, 3, "Resolved", "Network Security", "External services", "VPN portal", "Configuration scan", "Legacy protocols were disabled and the service configuration was retested.", 7, 2),
    ("N/A", "Unnecessary Network Service", "An unused network service was enabled on an internal server, increasing the available attack surface.", 2, 2, "Resolved", "Infrastructure Team", "Internal server estate", "FILE-SRV-02", "Hardening review", "The unused service was disabled and the host configuration was verified.", 10, 6),
    ("N/A", "Excessive User Permissions", "A shared application role grants more permissions than required for standard users.", 3, 4, "In Progress", "IAM Team", "Business application estate", "Procurement application", "Access review", "Apply least privilege by separating standard and elevated application roles.", 3, 1),
]


# Raised-by identities are deliberately varied to make the demonstration dataset
# resemble a real SOC workflow. Assignment/ownership remains independent.
INCIDENT_RAISERS = [
    ("joe.bloggs", "Joe Bloggs"),
    ("steven.frypan", "Steven Frypan"),
    ("natalie.airpod", "Natalie Airpod"),
    ("priya.shah", "Priya Shah"),
    ("marcus.green", "Marcus Green"),
    ("steven.frypan", "Steven Frypan"),
    ("natalie.airpod", "Natalie Airpod"),
]

VULNERABILITY_RAISERS = [
    ("natalie.airpod", "Natalie Airpod"),
    ("joe.bloggs", "Joe Bloggs"),
    ("priya.shah", "Priya Shah"),
    ("steven.frypan", "Steven Frypan"),
    ("marcus.green", "Marcus Green"),
    ("joe.bloggs", "Joe Bloggs"),
    ("natalie.airpod", "Natalie Airpod"),
    ("priya.shah", "Priya Shah"),
]


def main():
    with app.app_context():
        db.create_all()

        demo_users = [
            ("admin", "System", "Administrator", "Admin"),
            ("joe.bloggs", "Joe", "Bloggs", "Analyst"),
            ("steven.frypan", "Steven", "Frypan", "Analyst"),
            ("natalie.airpod", "Natalie", "Airpod", "Analyst"),
            ("priya.shah", "Priya", "Shah", "Analyst"),
            ("marcus.green", "Marcus", "Green", "Analyst"),
        ]
        for username, first_name, last_name, role in demo_users:
            if not User.query.filter_by(username=username).first():
                user = User(username=username, first_name=first_name, last_name=last_name, role=role)
                user.set_password("SecureTrackDemo123!")
                db.session.add(user)
        db.session.commit()

        if Incident.query.count() or Vulnerability.query.count():
            # Safe one-off refresh for an already-seeded demo database. Only the
            # standard demo references are touched; user-created records are left alone.
            updated = 0
            for idx, (username, full_name) in enumerate(INCIDENT_RAISERS, 1):
                item = Incident.query.filter(Incident.incident_number.endswith(f"-{idx:04d}")).first()
                if item and item.title == INCIDENTS[idx - 1][0]:
                    item.raised_by_username = username
                    item.raised_by_name = full_name
                    updated += 1
            for idx, (username, full_name) in enumerate(VULNERABILITY_RAISERS, 1):
                item = Vulnerability.query.filter(Vulnerability.vulnerability_number.endswith(f"-{idx:04d}")).first()
                if item and item.title == VULNERABILITIES[idx - 1][1]:
                    item.raised_by_username = username
                    item.raised_by_name = full_name
                    updated += 1
            db.session.commit()
            print(f"Updated raised-by attribution on {updated} existing demo records.")
            print("No user-created security records were changed.")
            return

        for idx, (title, description, category, severity, status, team, area, assets, source, impact_text, actions, days, hours) in enumerate(INCIDENTS, 1):
            created = dt(days, hours)
            db.session.add(Incident(
                incident_number=f"INC-{created.year}-{idx:04d}", title=title, description=description,
                category=category, occurred_at=created - timedelta(hours=1), raised_at=created,
                impacted_area=area, affected_assets=assets, detection_source=source,
                business_impact=impact_text, immediate_actions=actions, responsible_team=team,
                severity=severity, status=status, owner=["joe.bloggs", "steven.frypan", "natalie.airpod", "priya.shah", "marcus.green"][idx % 5],
                raised_by_username=INCIDENT_RAISERS[idx - 1][0],
                raised_by_name=INCIDENT_RAISERS[idx - 1][1], created_at=created, updated_at=created,
            ))

        for idx, (cve, title, description, likelihood, impact, status, team, area, assets, source, remediation, days, hours) in enumerate(VULNERABILITIES, 1):
            score, severity = calculate_risk(likelihood, impact)
            created = dt(days, hours)
            db.session.add(Vulnerability(
                vulnerability_number=f"VUL-{created.year}-{idx:04d}", cve_number=cve, title=title,
                description=description, impacted_area=area, affected_assets=assets, source=source,
                responsible_team=team, remediation_due=(created + timedelta(days=30)).date(),
                likelihood=likelihood, impact=impact, risk_score=score, severity=severity, status=status,
                owner=["natalie.airpod", "priya.shah", "marcus.green", "steven.frypan", "joe.bloggs"][idx % 5], remediation=remediation, raised_at=created,
                raised_by_username=VULNERABILITY_RAISERS[idx - 1][0],
                raised_by_name=VULNERABILITY_RAISERS[idx - 1][1], created_at=created, updated_at=created,
            ))

        db.session.add(AuditLog(username="System", action="Seed demo data", record_type="Demo Dataset",
                                details=f"Added {len(INCIDENTS)} incidents and {len(VULNERABILITIES)} vulnerabilities for demonstration/testing."))
        db.session.commit()
        print("SecureTrack demonstration data added successfully.")
        print("Demo users: admin, joe.bloggs, steven.frypan, natalie.airpod, priya.shah, marcus.green")
        print("Demo password: SecureTrackDemo123!")
        print("Demo users: admin, joe.bloggs, steven.frypan, natalie.airpod, priya.shah, marcus.green")
        print("Demo password for seeded accounts: SecureTrackDemo123!")
        print(f"Incidents: {len(INCIDENTS)}")
        print(f"Vulnerabilities: {len(VULNERABILITIES)}")
        print("Risk scores were calculated using SecureTrack's calculate_risk() business logic.")


if __name__ == "__main__":
    main()
