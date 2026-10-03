import copy
import unittest
from governance import evaluate,audit_batch,verify_chain

def request(**kwargs):
    row=dict(request_id='LAB-001',resource_id='DOC-001',role='engineer',purpose='operations',classification='internal',channel_trust='trusted',anomalous=False)
    row.update(kwargs);return row
class PolicyTests(unittest.TestCase):
    def test_allowed_internal(self):self.assertEqual(evaluate(request()).outcome,'allow')
    def test_sensitive_roles(self):
        self.assertEqual(evaluate(request(classification='sensitive')).outcome,'deny')
        self.assertEqual(evaluate(request(role='clinician',purpose='care',classification='sensitive')).outcome,'allow')
        self.assertEqual(evaluate(request(role='auditor',purpose='audit',classification='sensitive')).outcome,'allow')
    def test_purpose_mismatch(self):self.assertEqual(evaluate(request(purpose='care')).reason,'role_purpose_mismatch')
    def test_external(self):
        self.assertEqual(evaluate(request(role='external')).outcome,'deny')
        self.assertEqual(evaluate(request(role='external',classification='public')).outcome,'allow')
    def test_restricted(self):self.assertEqual(evaluate(request(classification='restricted')).reason,'restricted_resource')
    def test_unknown_classification(self):self.assertEqual(evaluate(request(classification='unknown')).outcome,'review')
    def test_untrusted_channel(self):self.assertEqual(evaluate(request(channel_trust='untrusted')).outcome,'deny')
    def test_unknown_channel(self):self.assertEqual(evaluate(request(channel_trust='unknown')).outcome,'review')
    def test_anomaly(self):self.assertEqual(evaluate(request(anomalous=True)).outcome,'review')
    def test_deny_precedes_anomaly(self):self.assertEqual(evaluate(request(classification='restricted',anomalous=True)).outcome,'deny')
    def test_invalid_context(self):
        for row in [request(role='admin'),request(anomalous='false'),{},None,request(resource_id=123)]:
            with self.subTest(row=row):self.assertEqual(evaluate(row).outcome,'review')
    def test_chain_and_tamper(self):
        rows=audit_batch([request(),request(request_id='LAB-002')])
        self.assertTrue(verify_chain(rows))
        changed=copy.deepcopy(rows);changed[0]['outcome']='deny'
        self.assertFalse(verify_chain(changed))
        self.assertFalse(verify_chain(list(reversed(rows))))
        self.assertFalse(verify_chain(rows[1:]))
    def test_no_document_content_in_audit(self):
        rows=audit_batch([request(content='synthetic secret',email='fake@example.test')])
        self.assertNotIn('content',rows[0]);self.assertNotIn('email',rows[0])
    def test_batch_validation(self):
        for rows in [{},[{}],[request(),request()]]:
            with self.subTest(rows=rows),self.assertRaises(ValueError):audit_batch(rows)
    def test_empty_chain(self):self.assertTrue(verify_chain(audit_batch([])))
    def test_invalid_chain(self):
        self.assertFalse(verify_chain({}));self.assertFalse(verify_chain([None]))
if __name__=='__main__':unittest.main()
