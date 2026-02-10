import unittest
from email.message import EmailMessage

from phish_analyzer.extractors import extract_urls
from phish_analyzer.indicators import parse_authentication_results, analyze_received_headers


class TestURLExtraction(unittest.TestCase):
    def test_extract_urls_plain_text(self):
        msg = EmailMessage()
        msg.set_content("Visit https://example.com/path, and http://example.org.")
        urls = extract_urls(msg)
        found = {u["url"] for u in urls}
        self.assertIn("https://example.com/path", found)
        self.assertIn("http://example.org", found)

    def test_extract_urls_html_entities(self):
        msg = EmailMessage()
        msg.add_alternative(
            "<html><body>Link: https://example.com/search?q=foo&amp;bar=baz</body></html>",
            subtype="html",
        )
        urls = extract_urls(msg)
        self.assertEqual(urls[0]["url"], "https://example.com/search?q=foo&bar=baz")

    def test_url_flags(self):
        msg = EmailMessage()
        msg.set_content(
            "http://127.0.0.1/login https://xn--exampl-9ta.com http://example.zip "
            "http://bit.ly/abc http://a.b.c.d.example.com:8080/path%20here "
            "https://exa-mple-foo-bar.com http://examp1e.com"
        )
        urls = extract_urls(msg, legit_domains=["example.com"])
        flags_map = {u["url"]: u["flags"] for u in urls}
        match_map = {u["url"]: u.get("homoglyph_matches", []) for u in urls}
        self.assertIn("ip_in_url", flags_map["http://127.0.0.1/login"])
        self.assertIn("punycode", flags_map["https://xn--exampl-9ta.com"])
        self.assertIn("suspicious_tld", flags_map["http://example.zip"])
        self.assertIn("url_shortener", flags_map["http://bit.ly/abc"])
        self.assertIn("excessive_subdomains", flags_map["http://a.b.c.d.example.com:8080/path%20here"])
        self.assertIn("suspicious_port", flags_map["http://a.b.c.d.example.com:8080/path%20here"])
        self.assertIn("encoded_path", flags_map["http://a.b.c.d.example.com:8080/path%20here"])
        self.assertIn("many_hyphens", flags_map["https://exa-mple-foo-bar.com"])
        self.assertIn("homoglyph_domain", flags_map["http://examp1e.com"])
        self.assertGreaterEqual(match_map["http://examp1e.com"][0]["severity"], 1)


class TestHeaderParsing(unittest.TestCase):
    def test_authentication_results_parsing(self):
        header = "mx.example.org; spf=pass smtp.mailfrom=example.org; dkim=fail; dmarc=pass"
        result = parse_authentication_results(header)
        self.assertTrue(result["found"])
        self.assertEqual(result["spf"], "pass")
        self.assertEqual(result["dkim"], "fail")
        self.assertEqual(result["dmarc"], "pass")

    def test_received_header_anomalies(self):
        received = [
            "from mail.test.local (10.0.0.5) by mx.example.com with ESMTP; Tue, 03 Feb 2026 10:00:00 -0000"
        ]
        analysis = analyze_received_headers(received)
        self.assertGreater(len(analysis["anomalies"]), 0)
        self.assertIn("private IP", " ".join(analysis["anomalies"]))


if __name__ == "__main__":
    unittest.main()
