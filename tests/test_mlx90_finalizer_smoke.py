import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FINALIZER = ROOT / "scripts" / "finalize-mlx90-delivery.py"


def load_finalizer():
    spec = importlib.util.spec_from_file_location(
        "mlx90_finalizer_smoke", FINALIZER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


class FinalizerImportSmokeTests(unittest.TestCase):
    def test_finalizer_module_loads_through_importlib(self):
        module = load_finalizer()
        self.assertTrue(callable(module.main))

    def test_json_writer_refuses_existing_files_and_symlinks(self):
        module = load_finalizer()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            existing = root / "existing.json"
            existing.write_text("ORIGINAL\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "output already exists"):
                module.write_json(existing, {"replacement": True})
            self.assertEqual("ORIGINAL\n", existing.read_text(encoding="utf-8"))

            symlink = root / "symlink.json"
            symlink.symlink_to(root / "missing-target.json")
            with self.assertRaisesRegex(ValueError, "output already exists"):
                module.write_json(symlink, {"replacement": True})
            self.assertTrue(symlink.is_symlink())
            self.assertFalse((root / "missing-target.json").exists())

    def test_json_writer_does_not_clobber_a_racing_target(self):
        module = load_finalizer()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "race.json"
            real_link = module.os.link

            def create_target_before_link(source, destination):
                Path(destination).write_text("RACE-WINNER\n", encoding="utf-8")
                return real_link(source, destination)

            with mock.patch.object(
                module.os,
                "link",
                side_effect=create_target_before_link,
            ):
                with self.assertRaisesRegex(ValueError, "output already exists"):
                    module.write_json(output, {"replacement": True})
            self.assertEqual(
                "RACE-WINNER\n", output.read_text(encoding="utf-8")
            )
            self.assertFalse(
                output.with_name(f".{output.name}.{module.os.getpid()}.tmp").exists()
            )


if __name__ == "__main__":
    unittest.main()
