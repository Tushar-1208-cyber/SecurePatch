from src.validator import run_regression_tests


def main():

    result = run_regression_tests(
        "workspace/sandbox_repo"
    )

    print("\n🧪 SECUREPATCH REGRESSION TEST")
    print("=" * 50)

    if result["passed"]:
        print("\n✅ ALL TESTS PASSED")
    else:
        print("\n❌ TESTS FAILED")

    print("\nTEST OUTPUT")
    print("-" * 50)

    print(result["output"])

    if result["errors"]:
        print("\nERRORS")
        print("-" * 50)
        print(result["errors"])


if __name__ == "__main__":
    main()
