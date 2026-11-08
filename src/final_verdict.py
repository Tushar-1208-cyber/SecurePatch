def generate_final_verdict(
    test_result: dict,
    security_result: dict
) -> dict:
    """
    Combine regression test validation and security
    validation to determine whether the AI patch
    should be accepted.
    """

    tests_passed = test_result["passed"]

    vulnerability_removed = security_result["secure"]

    accepted = (
        tests_passed
        and vulnerability_removed
    )

    if accepted:

        status = "VERIFIED"

        message = (
            "The patch passed regression tests and "
            "the target vulnerability was removed."
        )

    elif not vulnerability_removed and not tests_passed:

        status = "REJECTED"

        message = (
            "The target vulnerability still exists and "
            "regression tests failed."
        )

    elif not vulnerability_removed:

        status = "REJECTED"

        message = (
            "Regression tests passed, but the target "
            "security vulnerability still exists."
        )

    else:

        status = "REJECTED"

        message = (
            "The target vulnerability was removed, but "
            "regression tests failed."
        )

    return {
        "accepted": accepted,
        "status": status,
        "tests_passed": tests_passed,
        "vulnerability_removed": vulnerability_removed,
        "message": message
    }
