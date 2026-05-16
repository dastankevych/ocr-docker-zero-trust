import json
import unittest

from ocr.ocr import app
from ocr.zt_integration import allowed_page_origins, landing_manifest


class TrustedInputTests(unittest.TestCase):
    def test_allowed_page_origins_canonicalize_default_ports(self):
        origins = allowed_page_origins("http://demo.example:80")
        self.assertIn("http://demo.example", origins)
        self.assertIn("http://localhost", origins)
        self.assertIn("http://127.0.0.1", origins)
        self.assertNotIn("http://localhost:80", origins)
        self.assertNotIn("http://127.0.0.1:80", origins)

    def test_landing_manifest_uses_live_origin(self):
        manifest = landing_manifest("http://demo.example")
        self.assertEqual(manifest["endpoint_refs"][0]["origin"], "http://demo.example")
        self.assertEqual(
            manifest["endpoint_refs"][0]["attestation_url"],
            "http://demo.example/.well-known/attestation",
        )

    def test_page_embeds_manifest_and_trusted_input_annotations(self):
        client = app.test_client()
        response = client.get("/", headers={"Host": "demo.example"})
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn('type="application/ztbrowser-trusted-inputs+json"', html)
        self.assertIn('data-ztf-group="ocr"', html)
        self.assertIn('data-ztf-field="document"', html)
        self.assertIn('data-zts-group="ocr"', html)
        self.assertIn("http://demo.example/.well-known/attestation", html)

    def test_manifest_route_exposes_trusted_input_service(self):
        client = app.test_client()
        response = client.get("/zt-manifest", headers={"Host": "demo.example"})
        self.assertEqual(response.status_code, 200)
        manifest = response.get_json()
        claim = manifest["trusted_input_service"]
        self.assertEqual(claim["endpoint_origin"], "http://demo.example")
        self.assertIn("http://demo.example", claim["allowed_page_origins"])
        self.assertEqual(claim["profiles"][0]["submit"]["url"], "http://demo.example/v1/submit")


if __name__ == "__main__":
    unittest.main()
