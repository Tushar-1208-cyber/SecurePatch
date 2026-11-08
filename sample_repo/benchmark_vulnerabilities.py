"""
SecurePatch Multi-LLM Benchmark Vulnerabilities

INTENTIONALLY VULNERABLE.
DO NOT USE IN PRODUCTION.
"""


import hashlib
import sqlite3
import tarfile
import yaml


# ============================================================
# B307 - eval()
# ============================================================

def vulnerable_eval(expression):
    # INTENTIONAL B307
    return eval(expression)


# ============================================================
# B102 - exec()
# ============================================================

def vulnerable_exec(code):
    # INTENTIONAL B102
    exec(code)
    return True


# ============================================================
# B324 - weak MD5 hashing
# ============================================================

def vulnerable_md5(password):
    # INTENTIONAL B324
    return hashlib.md5(
        password.encode()
    ).hexdigest()


# ============================================================
# B506 - unsafe YAML loading
# ============================================================

def vulnerable_yaml(data):
    # INTENTIONAL B506
    return yaml.load(
        data,
        Loader=yaml.Loader
    )


# ============================================================
# B608 - SQL injection
# ============================================================

def vulnerable_sql(user_id):
    # INTENTIONAL B608
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    query = (
        "SELECT * FROM users WHERE id = "
        + user_id
    )

    cursor.execute(query)

    return cursor.fetchall()


# ============================================================
# B202 - unsafe tar extraction
# ============================================================

def vulnerable_tar_extract(archive, destination):
    # INTENTIONAL B202
    with tarfile.open(
        archive,
        "r"
    ) as tar:
        tar.extractall(destination)

    return True


# ============================================================
# B108 - insecure temporary file
# ============================================================

def vulnerable_temp_file():
    # INTENTIONAL B108
    filename = "/tmp/securepatch_temp.txt"

    with open(filename, "w") as handle:
        handle.write("temporary data")

    return filename


# ============================================================
# B105 - hardcoded password
# ============================================================

def vulnerable_password():
    # INTENTIONAL B105
    password = "SuperSecret123"

    return password


# These functions are intentionally not called.
# They exist only as static-analysis benchmark targets.
