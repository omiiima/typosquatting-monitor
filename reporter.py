import csv
import smtplib
from email.mime.text import MIMEText
import json
import os


SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = os.getenv("ALERT_EMAIL")
EMAIL_PASSWORD = os.getenv("ALERT_PASSWORD")


def save_csv(results, filename="report.csv"):
    fields = ["domain", "exists", "A", "http_code", "https_code", "final_url", "title", 
              "ssl_issuer", "ssl_subject","score"]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for r in results:
            writer.writerow({
                "domain": r["domain"],
                "exists": r["dns"]["exists"],
                "A": r["dns"]["A"],
                "http_code": r["http"]["http_code"],
                "https_code": r["http"]["https_code"],
                "final_url": r["http"]["final_url"],
                "title": r["title"],
                "ssl_issuer": r["ssl"]["issuer"],
                "ssl_subject": r["ssl"]["subject"],
                "score": r["score"]
            })

    print(f"[+] CSV saved as {filename}")

def get_high_score_domain(results):
    if not results:
        return [], 0
    
    total = sum(r["score"] for r in results)
    avg = total / len(results)

    above_avg = [r for r in results if r["score"] > avg]

    return above_avg, avg

def send_alert_email(domains, avg_score, to_email):

    """
    Send an alert email with domains above average score
    """

    subject = "Typosquatting Alert: High Risk Domains Detected"
    body = f"Average score : {avg_score:.2f}\n\nHigh risk domains:\n"
    for d in domains:
        body += f"- {d['domain']} (score: {d['score']})\n"


    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"[OK] Email alert sent to {to_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send alert email: {e}")

# send_alert_email(subject, body, to_email="chouafomaima@gmail.com")
