"""The SQL constants in bridge.py, checked without importing it (it needs
nats-py and asyncpg)."""

import ast
import os
import re
import unittest

from .helpers import CODE_DIR


def sql_constants():
    tree = ast.parse(open(os.path.join(CODE_DIR, "bridge.py")).read())
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    found[target.id] = node.value.value
    return found


class SqlConstantTests(unittest.TestCase):
    def test_reader_role_uses_balanced_dollar_quotes(self):
        """0.2.4 shipped 'DO $ ... END $;', which Postgres rejects, and the
        bridge crashed on start."""
        sql = sql_constants()["CREATE_READER_ROLE"]
        self.assertIn("DO $$", sql)
        self.assertIn("END $$;", sql)
        self.assertEqual(sql.count("$$"), 2)
        self.assertIsNone(re.search(r"(?<!\$)\$(?![$\d])", sql), "a lone $ outside $$ quoting")
        self.assertIn("GRANT SELECT ON scan_results TO samma_reader", sql)


if __name__ == "__main__":
    unittest.main()
