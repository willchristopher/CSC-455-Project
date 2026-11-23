import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from detector import FEATURE_NAMES, PhishingModel, analyze_url, extract_features, load_model
from evaluate import evaluate, is_test_site


class URLTests(unittest.TestCase):
    def test_hostname_is_separate_from_user_info(self):
        result = analyze_url("https://example.org:example-secret@192.0.2.10/")
        self.assertEqual(result.hostname, "192.0.2.10")
        self.assertEqual(result.site, "192.0.2.10")
        self.assertNotIn("example-secret", repr(result))

    def test_site_boundaries(self):
        for url, site in (
            ("https://help.example.co.uk", "example.co.uk"),
            ("https://www.city.kawasaki.jp", "city.kawasaki.jp"),
            ("https://project-a.github.io", "project-a.github.io"),
            ("https://[2001:db8::10]/", "2001:db8::10"),
            ("https://bücher.example/", "xn--bcher-kva.example"),
        ):
            with self.subTest(url=url):
                self.assertEqual(extract_features(url)[1], site)

    def test_related_urls_go_in_the_same_split(self):
        first = extract_features("http://www.example.org/help")[1]
        second = extract_features("https://shop.example.org/checkout")[1]
        self.assertEqual(first, second)
        self.assertEqual(is_test_site(first), is_test_site(second))

    def test_feature_order_and_scoring(self):
        url = "https://app-41.example.org/list?id=7&lang=en"
        _, _, features = extract_features(url)
        values = dict(zip(FEATURE_NAMES, features, strict=True))
        self.assertEqual(values["host_digits"], 2)
        self.assertEqual(values["subdomains"], 1)
        self.assertEqual(values["query_parameters"], 2)

        nodes = [
            {"feature": 0, "cutoff": 1.0, "left": 1, "right": 2},
            {"score": 0.1},
            {"score": 0.9},
        ]
        model = PhishingModel(nodes, 0.4)
        self.assertEqual(model.score([1]), 0.1)
        self.assertEqual(model.score([2]), 0.9)

        result = analyze_url(url)
        self.assertEqual(result.score, load_model().score(features))
        self.assertEqual(result.flagged, result.score >= load_model().threshold)

    def test_homepage_slash_does_not_change_score(self):
        self.assertEqual(analyze_url("https://www.example.org"),
                         analyze_url("https://www.example.org/"))

    def test_bad_input(self):
        for url in ("", "example.org", "https://example..org", "https://example.org..",
                    "https://example.org:", "https://example.org:99999",
                    "https://[2001:db8::10]abc/", "https://%ff.example.org/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                analyze_url(url)

    def test_evaluation_counts_both_errors(self):
        # Give each synthetic URL both labels to check every matrix cell.
        ordinary = "https://www.example.org/"
        unusual = "http://confirm-account-119.example.net/signin/check/8?session=abc"
        self.assertFalse(analyze_url(ordinary).flagged)
        self.assertTrue(analyze_url(unusual).flagged)
        with TemporaryDirectory() as folder:
            csv_path = Path(folder) / "test.csv"
            csv_path.write_text(
                f"URL,label\n{ordinary},0\n{ordinary},1\n{unusual},0\n{unusual},1\ninvalid,0\n",
                encoding="utf-8",
            )
            counts, skipped = evaluate(csv_path, phishing_label="1")
        self.assertEqual(counts, {"TP": 1, "FP": 1, "FN": 1, "TN": 1})
        self.assertEqual(skipped, {True: 0, False: 1})


if __name__ == "__main__":
    unittest.main()
