import subprocess
import json


def generate_domains(domain: str):
    """
    Returns a combined list of typographical variants
    """
    variants = set()
    try:
        result = subprocess.run(
            ["dnstwist", "-f","json","--registered", domain],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            data = json.loads(result.stdout)
            for item in data:
                if "domain" in item:
                    variants.add(item["domain"])
        else:
            print(f"[!] dnstwist error: {result.stderr}")

    except Exception as e:
        print(f"[!] dnstwist failed: {e}")

    return list(variants)
