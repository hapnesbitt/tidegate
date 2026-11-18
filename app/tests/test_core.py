"""Unit tests: python3 -m unittest discover -s app/tests (inside the image: see tests/lab/run.sh)."""
import tempfile
import time
import unittest
from types import SimpleNamespace

from tidegate import banner, headers, impostor, links, verdict
from tidegate.config import DEFAULTS, _merge, _namespace, _validate
from tidegate.store import Store, pattern_matches


def cfg(**filter_overrides):
    c = _namespace(_merge(DEFAULTS, {"gateway": {"domains": ["example.com"], "next_hop": "[mail.example.com]:25"},
                                     "filter": filter_overrides}))
    _validate(c)
    return c


def rspamd(score=0.0, action="no action", symbols=()):
    return {"score": score, "action": action, "symbols": {s: {"score": 1.0, "options": []} for s in symbols}}


class Impostor(unittest.TestCase):
    def analyze(self, frm, reply_to=None, symbols=(), vips=("Jane Smith",)):
        return {f.code: f.severity for f in impostor.analyze(
            from_header=frm, reply_to=reply_to, symbols=symbols, own_domains=["example.com"],
            protected_domains=["partner-bank.com"], vip_names=list(vips))}

    def test_lookalikes(self):
        for dom in ("examp1e.com", "exarnple.com", "example.co", "examples.com", "example-billing.com",
                    "xn--exmple-cua.com"):
            self.assertIn("lookalike_from", self.analyze(f"Billing <billing@{dom}>"), dom)

    def test_not_lookalikes(self):
        for dom in ("example.com", "mail.example.com", "gmail.com", "sample.org", "wikipedia.org"):
            self.assertNotIn("lookalike_from", self.analyze(f"Someone <someone@{dom}>"), dom)

    def test_own_domain_spoof_needs_failed_checks(self):
        self.assertEqual(self.analyze("CEO <ceo@example.com>", symbols={"R_SPF_FAIL"}).get("own_domain_spoof"), "high")
        self.assertEqual(self.analyze("CEO <ceo@example.com>", symbols={"DMARC_POLICY_REJECT"}).get("own_domain_spoof"), "high")
        self.assertNotIn("own_domain_spoof", self.analyze("CEO <ceo@example.com>", symbols={"R_SPF_FAIL", "R_DKIM_ALLOW"}))
        self.assertNotIn("own_domain_spoof", self.analyze("CEO <ceo@example.com>", symbols={"DMARC_POLICY_ALLOW"}))

    def test_vip_name(self):
        self.assertEqual(self.analyze("Jane Smith <jsmith.ceo@gmail.com>").get("vip_name_external"), "high")
        self.assertEqual(self.analyze('"Smith, Jane (CEO)" <x@evil.example>').get("vip_name_external"), "high")
        self.assertEqual(self.analyze("=?utf-8?q?Jane_Sm=C3=AFth?= <x@evil.example>").get("vip_name_external"), "high")
        self.assertNotIn("vip_name_external", self.analyze("Jane Smith <jane@example.com>"))
        self.assertNotIn("vip_name_external", self.analyze("Jane Doe <jane@other.example>"))

    def test_address_in_display_name(self):
        self.assertEqual(self.analyze('"ceo@example.com" <x@evil.example>').get("display_name_address"), "high")
        self.assertEqual(self.analyze('"ceo@example.com" <x@service.example>', symbols={"DMARC_POLICY_ALLOW"})
                         .get("display_name_address"), "medium")

    def test_reply_to_freemail(self):
        found = self.analyze("Jane Smith <jane@partner.example>", reply_to="jane.smith.ceo@gmail.com")
        self.assertIn("reply_to_freemail", found)


class Verdicts(unittest.TestCase):
    def test_order(self):
        c = cfg()
        self.assertEqual(verdict.decide(rspamd(20, "reject", {"CLAM_VIRUS"}), [], [], c).label, "quarantine:virus")
        self.assertEqual(verdict.decide(rspamd(20, "reject"), [], [], c).label, "quarantine:spam")
        self.assertEqual(verdict.decide(rspamd(7, "add header"), [], [], c).label, "deliver+tag")
        self.assertEqual(verdict.decide(rspamd(1), [], [], c).label, "deliver")
        high = [impostor.Finding("vip_name_external", "high", "x")]
        self.assertEqual(verdict.decide(rspamd(1), high, [], c).label, "quarantine:impostor")
        medium = [impostor.Finding("lookalike_from", "medium", "x")]
        self.assertEqual(verdict.decide(rspamd(1), medium, [], c).label, "deliver+warn")

    def test_scanner_failure(self):
        self.assertEqual(verdict.decide(rspamd(1, symbols={"CLAM_VIRUS_FAIL"}), [], [], cfg()).action, "defer")
        v = verdict.decide(rspamd(1, symbols={"CLAM_VIRUS_FAIL"}), [], [], cfg(fail_mode="open"))
        self.assertEqual(v.label, "deliver+unscanned")

    def test_observe_mode(self):
        c = cfg(quarantine_categories=["virus", "phish", "impostor"])
        self.assertEqual(verdict.decide(rspamd(30, "reject"), [], [], c).label, "deliver+observe-spam+tag")
        self.assertEqual(verdict.decide(rspamd(30, "reject", {"CLAM_VIRUS"}), [], [], c).label, "quarantine:virus")

    def test_allow_list_needs_proof(self):
        c = cfg()
        hit = [{"kind": "allow", "pattern": "partner.example", "scope": "everyone", "via": "from"}]
        self.assertEqual(verdict.decide(rspamd(20, "reject"), [], hit, c).label, "quarantine:spam")
        self.assertEqual(verdict.decide(rspamd(20, "reject", {"DMARC_POLICY_ALLOW"}), [], hit, c).label, "deliver")
        self.assertEqual(verdict.decide(rspamd(20, "reject", {"DMARC_POLICY_ALLOW", "CLAM_VIRUS"}), [], hit, c).label,
                         "quarantine:virus")


class Headers(unittest.TestCase):
    RAW = b"Received: from a\r\n by b\r\nX-Spamd-Result: forged\r\nSubject: hi\r\n\r\nbody\r\nX-Spamd-Result: in body\r\n"

    def test_edit_keeps_body(self):
        out = headers.edit(self.RAW, add=[("X-Tidegate-Verdict", "deliver")], remove={"x-spamd-result"})
        self.assertTrue(out.startswith(b"X-Tidegate-Verdict: deliver\r\nReceived: from a\r\n by b\r\n"))
        self.assertNotIn(b"forged", out)
        self.assertTrue(out.endswith(b"\r\n\r\nbody\r\nX-Spamd-Result: in body\r\n"))

    def test_unicode_value(self):
        out = headers.edit(b"Subject: x\n\nb", add=[("X-Tidegate-Warning", "Ünïcode name")])
        self.assertIn(b"=?utf-8?", out.split(b"\n")[0])


class Links(unittest.TestCase):
    def test_sign_verify(self):
        key = b"k" * 40
        tok = links.sign(key, "release", [7, "bob@example.com"], days=1)
        self.assertEqual(links.verify(key, tok, "release"), [7, "bob@example.com"])
        self.assertIsNone(links.verify(key, tok, "user"))
        self.assertIsNone(links.verify(b"x" * 40, tok, "release"))
        self.assertIsNone(links.verify(key, tok, "release", now=time.time() + 3 * 86400))
        self.assertIsNone(links.verify(key, tok[:-2] + "AA", "release"))


class StoreTests(unittest.TestCase):
    def test_quarantine_and_claim(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(d)
            qid = st.quarantine_add(b"Subject: x\n\nbody", sender="a@b.example", recipient="bob@example.com",
                                    category="spam", reasons=["r"], symbols=[])
            item = st.quarantine_get(qid)
            self.assertEqual(st.read_raw(item), b"Subject: x\n\nbody")
            self.assertTrue(st.claim(qid, "test"))
            self.assertFalse(st.claim(qid, "test"))

    def test_patterns(self):
        self.assertTrue(pattern_matches("example.org", "a@example.org"))
        self.assertFalse(pattern_matches("example.org", "a@sub.example.org"))
        self.assertTrue(pattern_matches("*.example.org", "a@sub.example.org"))
        self.assertTrue(pattern_matches("a@example.org", "A@Example.org"))


class Banner(unittest.TestCase):
    def test_plain_and_html(self):
        raw = (b"From: a@b.example\nSubject: s\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=X\n\n"
               b"--X\nContent-Type: text/plain\n\nhello\n--X\nContent-Type: text/html\n\n<html><body><p>hello</p></body></html>\n--X--\n")
        out = banner.add(raw, ["The From domain looks like example.com"])
        self.assertIn(b"impostor", out)
        self.assertIsNone(banner.add(b"Content-Type: multipart/signed; boundary=Y\n\n--Y--\n", ["x"]))


if __name__ == "__main__":
    unittest.main()
