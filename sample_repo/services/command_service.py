import shlex
import shutil
import subprocess


class CommandService:
    ALLOWED_COMMANDS = {
        "python",
        "python3",
        "git",
        "echo",
        "whoami",
    }

    def execute(self, command):
        # INTENTIONAL B602 VULNERABILITY
        # SecurePatch must detect and repair this.
        return subprocess.call(command, shell=True)

    def execute_safe(self, command):
        parts = shlex.split(command)

        if not parts:
            raise ValueError("Command is empty")

        if parts[0] not in self.ALLOWED_COMMANDS:
            raise ValueError("Command is not allowed")

        # Windows does not expose echo as a normal executable.
        # Keep this shell-free for testing.
        if parts[0].lower() == "echo":
            print(" ".join(parts[1:]))
            return 0

        result = subprocess.run(
            parts,
            shell=False,
            capture_output=True,
            text=True,
            check=False,
        )

        return result.returncode

    def command_exists(self, name):
        return shutil.which(name) is not None

    def version(self, executable):
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )

        return (
            result.stdout.strip()
            or result.stderr.strip()
        )