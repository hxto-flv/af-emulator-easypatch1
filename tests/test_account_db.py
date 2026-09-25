from pathlib import Path
import tempfile
import unittest

from server import account_db


class AccountDbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "accounts.sqlite3"
        self.old_rounds = account_db.PBKDF2_ITERATIONS
        account_db.PBKDF2_ITERATIONS = 1000

    def tearDown(self):
        account_db.PBKDF2_ITERATIONS = self.old_rounds
        self.tmp.cleanup()

    def test_create_verify_case_insensitive_and_duplicate(self):
        a = account_db.create_account("Player.One", "correct horse", db_path=self.db)
        self.assertEqual(a["uin"], 10001)
        self.assertIsNotNone(account_db.verify_account("player.one", "correct horse", db_path=self.db))
        self.assertIsNone(account_db.verify_account("player.one", "wrong pass", db_path=self.db))
        with self.assertRaises(account_db.DuplicateUsername):
            account_db.create_account("PLAYER.ONE", "another good password", db_path=self.db)

    def test_uins_increment_and_profile_rows_exist(self):
        a = account_db.create_account("alpha", "password1", db_path=self.db)
        b = account_db.create_account("bravo", "password2", db_path=self.db)
        self.assertEqual((a["uin"], b["uin"]), (10001, 10002))
        conn = account_db.connect(self.db)
        try:
            rows = conn.execute("SELECT uin,nickname FROM profiles ORDER BY uin").fetchall()
            self.assertEqual([(r["uin"], r["nickname"]) for r in rows], [(10001, None), (10002, None)])
        finally:
            conn.close()

    def test_sql_injection_style_username_is_rejected(self):
        with self.assertRaises(account_db.InvalidUsername):
            account_db.create_account("x' OR 1=1 --", "password1", db_path=self.db)
        self.assertEqual(account_db.account_count(db_path=self.db), 0)

    def test_disabled_account_cannot_login(self):
        a = account_db.create_account("disabled", "password1", db_path=self.db)
        conn = account_db.connect(self.db)
        try:
            conn.execute("UPDATE accounts SET status='disabled' WHERE uin=?", (a["uin"],))
            conn.commit()
        finally:
            conn.close()
        self.assertIsNone(account_db.verify_account("disabled", "password1", db_path=self.db))


if __name__ == "__main__":
    unittest.main()