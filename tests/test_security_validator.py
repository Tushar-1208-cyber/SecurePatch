from src.security_validator import validate_security


def main():

    result = validate_security(
        repo_path="workspace/sandbox_repo",
        original_rule_id="B602",
        original_filename="sample_repo/vulnerable_app.py",
        original_line=8
    )

    print("\n🛡️ SECUREPATCH SECURITY VALIDATION")
    print("=" * 50)

    print(
        f"\nTotal findings after patch: "
        f"{result['total_findings']}"
    )

    print(f"🔴 High: {result['high_count']}")
    print(f"🟠 Medium: {result['medium_count']}")
    print(f"🟡 Low: {result['low_count']}")

    if result["secure"]:

        print(
            "\n✅ TARGET VULNERABILITY REMOVED"
        )

    else:

        print(
            "\n❌ TARGET VULNERABILITY STILL EXISTS"
        )

        print("\nRemaining Findings:")

        for vuln in result["remaining_findings"]:

            print(
                f"- {vuln.rule_id} | "
                f"{vuln.filename} | "
                f"Line {vuln.line_number}"
            )


if __name__ == "__main__":
    main()
