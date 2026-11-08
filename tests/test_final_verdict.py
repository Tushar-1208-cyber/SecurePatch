from src.validator import run_regression_tests
from src.security_validator import validate_security
from src.final_verdict import generate_final_verdict


def main():

    repo_path = "workspace/sandbox_repo"

    print("\n⚖️ SECUREPATCH FINAL VERDICT")
    print("=" * 55)

    # -----------------------------------------
    # RUN REGRESSION TESTS
    # -----------------------------------------

    print("\n🧪 Running regression tests...")

    test_result = run_regression_tests(
        repo_path
    )

    if test_result["passed"]:
        print("Tests: PASSED ✅")
    else:
        print("Tests: FAILED ❌")

    # -----------------------------------------
    # RUN SECURITY VALIDATION
    # -----------------------------------------

    print("\n🛡️ Checking security vulnerability...")

    security_result = validate_security(
        repo_path=repo_path,
        original_rule_id="B602",
        original_filename="sample_repo/vulnerable_app.py",
        original_line=8
    )

    if security_result["secure"]:
        print(
            "Target vulnerability: REMOVED ✅"
        )
    else:
        print(
            "Target vulnerability: STILL EXISTS ❌"
        )

    # -----------------------------------------
    # GENERATE FINAL VERDICT
    # -----------------------------------------

    verdict = generate_final_verdict(
        test_result,
        security_result
    )

    print("\n" + "=" * 55)
    print("FINAL PATCH STATUS")
    print("=" * 55)

    print(f"\nStatus: {verdict['status']}")

    print(
        f"\nRegression Tests: "
        f"{'PASSED ✅' if verdict['tests_passed'] else 'FAILED ❌'}"
    )

    print(
        f"Security Validation: "
        f"{'PASSED ✅' if verdict['vulnerability_removed'] else 'FAILED ❌'}"
    )

    print(f"\nResult: {verdict['message']}")

    if verdict["accepted"]:

        print("\n🟢 SECURE PATCH VERIFIED")

    else:

        print("\n🔴 PATCH REJECTED")


if __name__ == "__main__":
    main()
