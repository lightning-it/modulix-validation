import unittest
from pathlib import Path


class AapIncusNightlyContractTests(unittest.TestCase):
    def test_public_cross_repository_checkouts_have_read_only_fallback(self):
        workflow = (
            Path(__file__).parents[1] / ".github/workflows/aap-incus-nightly.yml"
        ).read_text(encoding="utf-8")

        fallback = (
            "token: ${{ secrets.LIT_REPOSITORY_READ_TOKEN || github.token }}"
        )
        self.assertEqual(workflow.count(fallback), 8)
        self.assertNotIn(
            "token: ${{ secrets.LIT_REPOSITORY_READ_TOKEN }}", workflow
        )
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("timeout-minutes: 15", workflow)
        self.assertIn("timeout-minutes: 330", workflow)


if __name__ == "__main__":
    unittest.main()
