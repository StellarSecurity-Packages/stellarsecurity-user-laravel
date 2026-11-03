import ast
import base64
import hashlib
from pathlib import Path
import re
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[1]
OLD_SOURCE = '9c3cffad2daf0313baf993e9028fa277a5a775921270201f52da92a411503e42'
OLD_WORKFLOW = 'd9f1d6c3c98637b3accd81cb1404dd842398ae24dd19248d9654f3449d926ccc'
WORKER = '484b99b4b9bc4b08180690b0469c8f0d2e2af05b2e1a4ea3d7029698ccc8b27c'


class WeeklyCollectorIntegrity(unittest.TestCase):
    def test_only_the_expected_schedule_literal_changes_in_the_collector(self):
        workflow = (ROOT / '.github/workflows/stellar-commit-trigger.yml').read_bytes()
        chunks = re.findall(rb"base64\.b64decode\('([^']+)'", workflow)
        packed_copies = b''.join(base64.b64decode(chunk, validate=True) for chunk in chunks)
        self.assertEqual(len(packed_copies) % 3, 0)
        packed = packed_copies[:len(packed_copies) // 3]
        self.assertEqual(packed_copies, packed * 3)
        decoder = zlib.decompressobj()
        source = decoder.decompress(packed, 200000)
        self.assertTrue(decoder.eof)
        self.assertEqual(decoder.unused_data, b'')
        weekly = b"    - cron: '23 4 * * 1'"
        self.assertEqual(source.count(weekly), 1)
        original = source.replace(weekly, b"    - cron: '23 */6 * * *'", 1)
        self.assertEqual(hashlib.sha256(original).hexdigest(), OLD_SOURCE)
        self.assertEqual(workflow.count(weekly), 1)
        self.assertEqual(hashlib.sha256((ROOT / '.github/workflows/stellar-commit-guard.yml').read_bytes()).hexdigest(), WORKER)

        # Execute only the inspected text-formatting functions, never the collector.
        functions = [node for node in ast.parse(source).body
                     if isinstance(node, ast.FunctionDef) and node.name in {'sha256', 'payload_steps', 'render_workflow'}]
        self.assertEqual({node.name for node in functions}, {'sha256', 'payload_steps', 'render_workflow'})
        scope = {'base64': base64, 'hashlib': hashlib, 're': re, 'zlib': zlib, 'Halt': RuntimeError}
        exec(compile(ast.Module(body=functions, type_ignores=[]), 'reviewed-workflow-formatter', 'exec'), scope)
        self.assertEqual(hashlib.sha256(scope['render_workflow'](original)).hexdigest(), OLD_WORKFLOW)
        self.assertEqual(scope['render_workflow'](source), workflow)
        source_check = ("if self.file(TRIGGER, head) != expected_trigger or "
                        "sha256(self.file(WORKER, head)) != WORKER_SHA256:")
        self.assertIn(source_check, source.decode())


if __name__ == '__main__':
    unittest.main()
