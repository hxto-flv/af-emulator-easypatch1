from pathlib import Path
import tempfile
import unittest

from server import account_db
from web.account_service import _account_by_uin, _init_web_schema, _register, _verify_web_account
from web.admin_service import (
    _bootstrap_admin,
    _create_invite,
    _issue_recovery_codes,
    _recover,
    _set_banned,
)


class WebAccountServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "web.sqlite3"
        self.old_rounds = account_db.PBKDF2_ITERATIONS
        account_db.PBKDF2_ITERATIONS = 1000
        _init_web_schema(self.db)

    def tearDown(self):
        account_db.PBKDF2_ITERATIONS = self.old_rounds
        self.tmp.cleanup()

    def test_invite_is_consumed_transactionally(self):
        admin = account_db.create_account("admin1", "password1", db_path=self.db)
        _bootstrap_admin(self.db, "admin1", "password1")
        code = _create_invite(self.db, admin["uin"], "beta", 1, 24)
        made = _register(self.db, "player1", "password2", code, True, "127.0.0.1")
        self.assertEqual(made["uin"], 10002)
        with self.assertRaises(account_db.AccountError):
            _register(self.db, "player2", "password3", code, True, "127.0.0.1")

    def test_recovery_code_is_one_time_and_changes_password(self):
        user = account_db.create_account("recoverme", "password1", db_path=self.db)
        codes = _issue_recovery_codes(self.db, user["uin"])
        self.assertEqual(len(codes), 3)
        self.assertTrue(_recover(self.db, "recoverme", codes[0], "password2", "127.0.0.1"))
        self.assertIsNone(account_db.verify_account("recoverme", "password1", db_path=self.db))
        self.assertIsNotNone(account_db.verify_account("recoverme", "password2", db_path=self.db))
        self.assertFalse(_recover(self.db, "recoverme", codes[0], "password3", "127.0.0.1"))

    def test_ban_blocks_login_and_recovery(self):
        user = account_db.create_account("banned1", "password1", db_path=self.db)
        codes = _issue_recovery_codes(self.db, user["uin"])
        _set_banned(self.db, user["uin"], True, "test")
        self.assertIsNone(_verify_web_account(self.db, "banned1", "password1", "127.0.0.1"))
        self.assertFalse(_recover(self.db, "banned1", codes[0], "password2", "127.0.0.1"))
        self.assertTrue(_account_by_uin(self.db, user["uin"])["is_banned"])

    def test_admin_bootstrap_requires_existing_password(self):
        account_db.create_account("owner", "password1", db_path=self.db)
        with self.assertRaises(account_db.AccountError):
            _bootstrap_admin(self.db, "owner", "wrongpass")
        _bootstrap_admin(self.db, "owner", "password1")
        self.assertTrue(_account_by_uin(self.db, 10001)["is_admin"])


if __name__ == "__main__":
    unittest.main()