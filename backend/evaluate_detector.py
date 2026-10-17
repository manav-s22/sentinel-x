
from app.main import analyze_url


# These are controlled test scenarios, not verified real-world
# phishing or benign labels. No URLs are visited.
CASES = [
    {
        "name": "Ordinary HTTPS example",
        "url": "https://example.com",
        "expected_signals": [],
    },
    {
        "name": "HTTP without encryption",
        "url": "http://example.com",
        "expected_signals": ["No HTTPS"],
    },
    {
        "name": "Sensitive login path",
        "url": "https://example.com/login",
        "expected_signals": ["Sensitive-action keywords"],
    },
    {
        "name": "IP address and login path",
        "url": "http://192.0.2.1/login",
        "expected_signals": [
            "No HTTPS",
            "IP address hostname",
            "Sensitive-action keywords",
        ],
    },
    {
        "name": "URL shortener",
        "url": "https://bit.ly/example",
        "expected_signals": ["URL shortener"],
    },
    {
        "name": "Hostname with a review-list TLD",
        "url": "https://example.xyz",
        "expected_signals": ["TLD worth reviewing"],
    },
    {
        "name": "Many subdomain levels",
        "url": "https://a.b.c.d.example.com",
        "expected_signals": ["Many subdomains"],
    },
    {
        "name": "Punycode hostname",
        "url": "https://xn--pple-43d.com",
        "expected_signals": ["Punycode hostname"],
    },
    {
        "name": "URL embedded in query",
        "url": "https://example.com/redirect?next=https://other.test",
        "expected_signals": ["Embedded URL in query"],
    },
    {
        "name": "User-info destination ambiguity",
        "url": "https://example.com@other.test/login",
        "expected_signals": [
            "URL contains @",
            "Sensitive-action keywords",
        ],
    },
]


def main():
    passed = 0
    failed = 0

    print("\nSENTINEL X — HEURISTIC RULE COVERAGE")
    print("=" * 78)
    print("Controlled examples only; this is not a real-world accuracy benchmark.")
    print("-" * 78)

    for case in CASES:
        result = analyze_url(case["url"])
        actual_signals = {
            signal["signal"]
            for signal in result["signals"]
            if signal["points"] > 0
        }

        missing = set(case["expected_signals"]) - actual_signals
        status = "PASS" if not missing else "FAIL"

        if status == "PASS":
            passed += 1
        else:
            failed += 1

        print(f"\n[{status}] {case['name']}")
        print(f"  URL: {case['url']}")
        print(
            f"  Score: {result['risk_score']}/100"
            f" | Level: {result['risk_level']}"
        )
        print(f"  Signals: {', '.join(sorted(actual_signals)) or 'None'}")

        if missing:
            print(f"  Missing expected signals: {', '.join(sorted(missing))}")

    total = len(CASES)

    print("\n" + "=" * 78)
    print(f"Rule coverage checks passed: {passed}/{total}")
    print(f"Rule coverage checks failed: {failed}/{total}")
    print(
        "\nInterpretation: this checks whether selected rules activate "
        "for controlled examples. It does NOT measure phishing detection "
        "accuracy, precision, recall, or real-world safety."
    )

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
