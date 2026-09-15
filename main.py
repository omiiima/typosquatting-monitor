# main.py
from name_generator import generate_domains
from scanner import scan_domain
from reporter import save_csv, get_high_score_domain, send_alert_email

def main():
    target = input("Enter domain to monitor: ").strip()

    print(f"\n[+] Generating domain variants for: {target}")
    variants = generate_domains(target)
    print(f"[+] {len(variants)} variants generated.\n")

    results = []

    # Scan all variants
    for d in variants:
        print(f"Scanning: {d}")
        scan_result = scan_domain(d)
        results.append(scan_result)

    # Sort by score descending and take top 10
    top10 = sorted(results, key=lambda x: x["score"], reverse=True)[:10]

    save_csv(top10, filename=f"output/{target}_typosquatting_report.csv")

    send_alert_email(
        domains=top10,
        avg_score=sum(r["score"] for r in top10) / len(top10),
        #to_email="Contact-Technique@drsd.fr"
        to_email="ochouaf@enseirb-matmeca.fr"
    )

    # Show top 10 suspicious domains
    print("\n=== TOP 10 MOST SUSPICIOUS DOMAINS ===")
    for i, r in enumerate(top10, start=1):
        print(f"{i}. {r['domain']}  --> score {r['score']}")


if __name__ == "__main__":
    main()
