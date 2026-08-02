"""Regression tests for hermetic Terraform repository-quality validation."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lit-repository-quality.py"
SPEC = importlib.util.spec_from_file_location("lit_repository_quality", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {SCRIPT}")
QUALITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALITY)


class RepositoryQualityTerraformTests(unittest.TestCase):
    def test_policy_copies_once_and_isolates_root_data_dirs(self) -> None:
        observed_data_dirs: list[str] = []
        observed_commands: list[list[str]] = []

        def capture_data_dir(command: list[str]) -> None:
            observed_commands.append(command)
            if "init" in command or "validate" in command:
                observed_data_dirs.append(os.environ["TF_DATA_DIR"])

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            root = temporary_root / "repo"
            root.mkdir()
            executable_temp = temporary_root / "executable-temp"
            executable_temp.mkdir()
            for name in ("first", "second"):
                policy = root / "terraform" / name
                policy.mkdir(parents=True)
                (policy / "versions.tf").write_text(
                    "terraform {}\n",
                    encoding="utf-8",
                )
            original_copytree = QUALITY.shutil.copytree
            with mock.patch.object(QUALITY, "ROOT", root), \
                 mock.patch.object(
                     QUALITY,
                     "shutil_which",
                     return_value="/usr/bin/terraform",
                 ), \
                 mock.patch.object(
                     QUALITY.shutil,
                     "copytree",
                     wraps=original_copytree,
                 ) as copytree, \
                 mock.patch.object(
                     QUALITY,
                     "run",
                     side_effect=capture_data_dir,
                 ), \
                 mock.patch.dict(
                     os.environ,
                     {"HOME": str(executable_temp)},
                     clear=True,
                 ):
                QUALITY.check_terraform("terraform_policy")

        top_level_copies = [
            call
            for call in copytree.call_args_list
            if Path(call.args[0]) == root
        ]
        self.assertEqual(1, len(top_level_copies))
        fmt_commands = [command for command in observed_commands if "fmt" in command]
        self.assertEqual(1, len(fmt_commands))
        fmt_command = fmt_commands[0]
        self.assertEqual(["fmt", "-check", "-recursive"], fmt_command[2:])
        self.assertTrue(fmt_command[1].startswith("-chdir="))
        fmt_workspace = Path(fmt_command[1].split("=", 1)[1])
        self.assertEqual("workspace", fmt_workspace.name)
        self.assertEqual(executable_temp.resolve(), fmt_workspace.parent.parent.resolve())
        self.assertEqual(4, len(observed_data_dirs))
        self.assertEqual(observed_data_dirs[0], observed_data_dirs[1])
        self.assertEqual(observed_data_dirs[2], observed_data_dirs[3])
        self.assertNotEqual(observed_data_dirs[0], observed_data_dirs[2])

    def test_validation_rejects_symlinks_before_any_terraform_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            root = temporary_root / "repo"
            root.mkdir()
            executable_temp = temporary_root / "executable-temp"
            executable_temp.mkdir()
            external_file = temporary_root / "external.tf"
            external_file.write_text(
                "resource \"null_resource\" \"external\" {}\n",
                encoding="utf-8",
            )
            (root / "main.tf").write_text("terraform {}\n", encoding="utf-8")
            (root / "linked.tf").symlink_to(external_file)

            with mock.patch.object(QUALITY, "ROOT", root), \
                 mock.patch.object(
                     QUALITY,
                     "shutil_which",
                     return_value="/usr/bin/terraform",
                 ), \
                 mock.patch.object(QUALITY, "run") as run, \
                 mock.patch.dict(
                     os.environ,
                     {"HOME": str(executable_temp)},
                     clear=True,
                 ):
                with self.assertRaisesRegex(
                    AssertionError,
                    r"workspace may not contain symlinks: linked\.tf",
                ):
                    QUALITY.check_terraform("terraform_module")

            run.assert_not_called()

    def test_validation_rejects_directory_symlink_before_terraform(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            root = temporary_root / "repo"
            root.mkdir()
            executable_temp = temporary_root / "executable-temp"
            executable_temp.mkdir()
            external_directory = temporary_root / "external"
            external_directory.mkdir()
            (external_directory / "external.tf").write_text(
                "resource \"null_resource\" \"external\" {}\n",
                encoding="utf-8",
            )
            (root / "main.tf").write_text("terraform {}\n", encoding="utf-8")
            (root / "linked-directory").symlink_to(
                external_directory,
                target_is_directory=True,
            )

            with mock.patch.object(QUALITY, "ROOT", root), \
                 mock.patch.object(
                     QUALITY,
                     "shutil_which",
                     return_value="/usr/bin/terraform",
                 ), \
                 mock.patch.object(QUALITY, "run") as run, \
                 mock.patch.dict(
                     os.environ,
                     {"HOME": str(executable_temp)},
                     clear=True,
                 ):
                with self.assertRaisesRegex(
                    AssertionError,
                    r"workspace may not contain symlinks: linked-directory",
                ):
                    QUALITY.check_terraform("terraform_module")

            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
