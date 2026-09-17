import json
import os
import re
import unittest

from soc_log_anonymizer.config import AnonymizerConfig


ROOT = os.path.dirname(os.path.dirname(__file__))


class TestDocumentationExamples(unittest.TestCase):
    def test_readme_local_links_exist(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
            readme = handle.read()
        links = re.findall(r"\]\((?!https?://|#)([^)]+)\)", readme)
        for link in links:
            path = link.split("#", 1)[0].split("?", 1)[0]
            self.assertTrue(path, link)
            self.assertTrue(os.path.exists(os.path.join(ROOT, path)), link)

    def test_example_configs_load_and_validate(self):
        examples = os.path.join(ROOT, "examples")
        for name in ("sample_config.json", "sample_config.ini"):
            path = os.path.join(examples, name)
            config = AnonymizerConfig.load(path)
            self.assertEqual(config.validate(), [], name)

    def test_sample_json_is_valid(self):
        with open(os.path.join(ROOT, "examples", "sample_config.json"),
                  encoding="utf-8") as handle:
            self.assertIsInstance(json.load(handle), dict)


if __name__ == "__main__":
    unittest.main()
