# Managed by lightning-it/shared-assets-lit.

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
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            environment = {
                "HOME": str(temporary_root),
                "PATH": os.environ.get("PATH") or os.defpath,
                "WUNDER_CONTAINER_ENGINE": engine,
                "WUNDER_DEVTOOLS_DOCKER_SOCKET": "disabled",
                "WUNDER_DEVTOOLS_RUN_AS_HOST_UID": "1",
                "FAKE_ROOTLESS": "true" if rootless else "false",
            }
            # Exported Bash functions emulate only the two container-engine
            # calls the wrapper makes. No executable fixture is written to a
            # host or container temporary filesystem, which remains noexec.
            harness = r"""
fake_engine() {
  if [ "${1:-}" = "info" ]; then
    printf '%s\n' "${FAKE_ROOTLESS:-false}"
    return 0
  fi
  printf '%s\n' "$@"
}
docker() { fake_engine "$@"; }
podman() { fake_engine "$@"; }
export -f fake_engine docker podman
exec /bin/bash "$1" true
"""
            result = subprocess.run(
                ["/bin/bash", "-c", harness, "wunder-test", str(WRAPPER)],
                cwd=temporary_root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            return result.stdout.splitlines()

    def test_host_uid_run_tmpfs_matches_container_identity(self) -> None:
        cases = (
            ("docker", False, os.getuid(), os.getgid(), True),
            ("podman", False, os.getuid(), os.getgid(), True),
            ("podman", True, 0, 0, False),
        )
        for engine, rootless, expected_uid, expected_gid, includes_identity in cases:
            with self.subTest(engine=engine, rootless=rootless):
                arguments = self.wrapper_args(engine, rootless=rootless)
                self.assertEqual(
                    f"{expected_uid}:{expected_gid}",
                    arguments[arguments.index("--user") + 1],
                )
                run_mount = next(
                    argument for argument in arguments if argument.startswith("/run:")
                )
                if includes_identity:
                    expected_mount = (
                        "/run:rw,nosuid,nodev,size=256m,"
                        f"uid={expected_uid},gid={expected_gid},mode=0755"
                    )
                else:
                    expected_mount = "/run:rw,nosuid,nodev,size=256m,mode=0755"
                    self.assertNotIn("uid=", run_mount)
                    self.assertNotIn("gid=", run_mount)
                self.assertEqual(expected_mount, run_mount)
                self.assertNotIn("mode=1777", run_mount)

    def test_wrapper_args_do_not_require_ambient_home_or_path(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            arguments = self.wrapper_args("docker", rootless=False)
        self.assertEqual(
            f"{os.getuid()}:{os.getgid()}",
            arguments[arguments.index("--user") + 1],
        )

if __name__ == "__main__":
    unittest.main()
