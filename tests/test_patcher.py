from src.patcher import (
    create_sandbox,
    apply_function_patch
)


def main():

    repo_path = "sample_repo"

    old_function = """def run_command(user_input):
    subprocess.call(user_input, shell=True)
"""

    new_function = """def run_command(user_input):
    subprocess.call(user_input.split(), shell=False)
"""

    print("\n📦 Creating sandbox...")

    sandbox = create_sandbox(repo_path)

    print(f"Sandbox created at: {sandbox}")

    patched_file = apply_function_patch(
        original_file="sample_repo/vulnerable_app.py",
        sandbox_repo=sandbox,
        old_function=old_function,
        new_function=new_function
    )

    print("\n🔧 Patch applied successfully!")

    print(f"\nPatched file: {patched_file}")

    print("\n📄 PATCHED CODE")
    print("=" * 50)

    print(
        patched_file.read_text()
    )


if __name__ == "__main__":
    main()