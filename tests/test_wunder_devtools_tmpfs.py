import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "wunder-devtools-ee.sh"


class WunderDevtoolsTmpfsTests(unittest.TestCase):
    def wrapper_args(self, engine: str, *, rootless: bool) -> list[str]:
        home = os.environ.get("HOME")
        temporary_parent = Path(home) if home else Path("/tmp/wunder")
        try:
            temporary = tempfile.TemporaryDirectory(dir=temporary_parent)
        except OSError:
            temporary = tempfile.TemporaryDirectory()
        with temporary as temporary_directory:
            temporary_root = Path(temporary_directory)
            fake_engine = temporary_root / engine
            fake_engine.write_text(
                """#!/bin/sh
if [ "${1:-}" = "info" ]; then
  printf '%s\\n' "${FAKE_ROOTLESS:-false}"
  exit 0
fi
printf '%s\\n' "$@"
""",
                encoding="utf-8",
            )
            fake_engine.chmod(0o700)
            environment = {
                "HOME": str(temporary_root),
                "PATH": f"{temporary_root}:{os.environ.get('PATH') or os.defpath}",
                "WUNDER_CONTAINER_ENGINE": engine,
                "WUNDER_DEVTOOLS_DOCKER_SOCKET": "disabled",
                "WUNDER_DEVTOOLS_RUN_AS_HOST_UID": "1",
                "FAKE_ROOTLESS": "true" if rootless else "false",
            }
            result = subprocess.run(
                ["bash", str(WRAPPER), "true"],
                cwd=temporary_root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            return result.stdout.splitlines()

    def test_host_uid_run_tmpfs_matches_container_identity(self):
        cases = (
            ("docker", False, os.getuid(), os.getgid()),
            ("podman", False, os.getuid(), os.getgid()),
            ("podman", True, 0, 0),
        )
        for engine, rootless, expected_uid, expected_gid in cases:
            with self.subTest(engine=engine, rootless=rootless):
                arguments = self.wrapper_args(engine, rootless=rootless)
                self.assertEqual(
                    f"{expected_uid}:{expected_gid}",
                    arguments[arguments.index("--user") + 1],
                )
                run_mount = next(
                    argument
                    for argument in arguments
                    if argument.startswith("/run:")
                )
                self.assertEqual(
                    "/run:rw,nosuid,nodev,size=256m,"
                    f"uid={expected_uid},gid={expected_gid},mode=0755",
                    run_mount,
                )
                self.assertNotIn("mode=1777", run_mount)

    def test_wrapper_args_do_not_require_ambient_home_or_path(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            arguments = self.wrapper_args("docker", rootless=False)
        self.assertEqual(
            f"{os.getuid()}:{os.getgid()}",
            arguments[arguments.index("--user") + 1],
        )


if __name__ == "__main__":
    unittest.main()
