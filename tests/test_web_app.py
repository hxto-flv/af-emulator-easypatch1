from pathlib import Path
import re
import tempfile
import unittest

try:
    from web.app import create_app
    from server import account_db
except ModuleNotFoundError as exc:  # lets stdlib-only environments still discover tests
    create_app = None
    account_db = None
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not match:
        raise AssertionError("CSRF token not found")
    return match.group(1)


@unittest.skipIf(create_app is None, f"Flask dependency unavailable: {IMPORT_ERROR}")
class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "web.sqlite3")
        self.old_rounds = account_db.PBKDF2_ITERATIONS
        account_db.PBKDF2_ITERATIONS = 1000
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "ACCOUNT_DB": self.db,
            "REQUIRE_INVITE": False,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        account_db.PBKDF2_ITERATIONS = self.old_rounds
        self.tmp.cleanup()

    def post_with_csrf(self, url: str, data: dict, source: str = "/login"):
        html = self.client.get(source).get_data(as_text=True)
        payload = dict(data)
        payload["csrf_token"] = csrf_from(html)
        return self.client.post(url, data=payload, follow_redirects=False)

    def test_register_login_and_account(self):
        response = self.post_with_csrf(
            "/register",
            {"username": "player1", "password": "password1", "confirm_password": "password1"},
            source="/register",
        )
        self.assertEqual(response.status_code, 200)
        response = self.post_with_csrf(
            "/login",
            {"username": "player1", "password": "password1"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"].rsplit("/", 1)[-1], "account")
        self.assertEqual(self.client.get("/account").status_code, 200)

    def test_admin_is_hidden_from_normal_users(self):
        account_db.create_account("player2", "password2", db_path=self.db)
        self.post_with_csrf("/login", {"username": "player2", "password": "password2"})
        self.assertEqual(self.client.get("/admin").status_code, 404)

    def test_banned_user_cannot_login(self):
        user = account_db.create_account("player3", "password3", db_path=self.db)
        conn = account_db.connect(self.db)
        try:
            conn.execute("INSERT OR IGNORE INTO web_account_flags(uin) VALUES(?)", (user["uin"],))
            conn.execute("UPDATE web_account_flags SET is_banned=1 WHERE uin=?", (user["uin"],))
            conn.commit()
        finally:
            conn.close()
        response = self.post_with_csrf("/login", {"username": "player3", "password": "password3"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid username or password", response.get_data(as_text=True))

    def test_post_without_csrf_is_rejected(self):
        response = self.client.post("/login", data={"username": "x", "password": "password1"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()