import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote
from unittest.mock import patch

import src.app as app_module


TEST_PASSWORD = "correct horse battery staple"


async def asgi_request(application, method, target, headers=None, body=b""):
    path, _, query = target.partition("?")
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    response_messages = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        response_messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": unquote(path),
        "raw_path": path.encode("utf-8"),
        "query_string": query.encode("ascii"),
        "root_path": "",
        "headers": headers or [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    await application(scope, receive, send)

    status = next(
        message["status"]
        for message in response_messages
        if message["type"] == "http.response.start"
    )
    response_headers = dict(
        next(
            message["headers"]
            for message in response_messages
            if message["type"] == "http.response.start"
        )
    )
    response_body = b"".join(
        message.get("body", b"")
        for message in response_messages
        if message["type"] == "http.response.body"
    )
    return status, response_headers, response_body


class AdminAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.accounts_file = Path(self.temp_dir.name) / "teachers.json"
        self.accounts_file.write_text(
            json.dumps({
                "teachers": [{
                    "username": "teacher1",
                    **app_module.hash_teacher_password(TEST_PASSWORD),
                }]
            }),
            encoding="utf-8",
        )
        self.accounts_patch = patch.object(app_module, "TEACHERS_FILE", self.accounts_file)
        self.secret_patch = patch.object(app_module, "SESSION_SECRET", b"test-session-secret")
        self.accounts_patch.start()
        self.secret_patch.start()
        self.original_participants = list(app_module.activities["Chess Club"]["participants"])

    def tearDown(self):
        app_module.activities["Chess Club"]["participants"] = self.original_participants
        self.secret_patch.stop()
        self.accounts_patch.stop()
        self.temp_dir.cleanup()

    def request(self, method, target, headers=None, body=b""):
        return asyncio.run(asgi_request(app_module.app, method, target, headers, body))

    def teacher_cookie(self):
        status, headers, _ = self.request(
            "POST",
            "/auth/login",
            headers=[(b"content-type", b"application/json")],
            body=json.dumps({"username": "teacher1", "password": TEST_PASSWORD}).encode(),
        )
        self.assertEqual(status, 200)
        return headers[b"set-cookie"].decode().split(";", 1)[0].encode()

    def test_public_activity_list_and_mutations_require_teacher(self):
        status, _, _ = self.request("GET", "/activities")
        self.assertEqual(status, 200)

        status, _, _ = self.request(
            "POST", "/activities/Chess%20Club/signup?email=new%40school.edu"
        )
        self.assertEqual(status, 401)

        status, _, _ = self.request(
            "DELETE", "/activities/Chess%20Club/unregister?email=michael%40mergington.edu"
        )
        self.assertEqual(status, 401)
        self.assertEqual(
            app_module.activities["Chess Club"]["participants"],
            self.original_participants,
        )

    def test_teacher_can_sign_up_and_unregister(self):
        cookie = self.teacher_cookie()
        headers = [(b"cookie", cookie)]

        status, _, _ = self.request(
            "POST",
            "/activities/Chess%20Club/signup?email=new%40school.edu",
            headers=headers,
        )
        self.assertEqual(status, 200)

        status, _, _ = self.request(
            "DELETE",
            "/activities/Chess%20Club/unregister?email=new%40school.edu",
            headers=headers,
        )
        self.assertEqual(status, 200)

    def test_invalid_teacher_password_is_rejected(self):
        status, _, _ = self.request(
            "POST",
            "/auth/login",
            headers=[(b"content-type", b"application/json")],
            body=json.dumps({"username": "teacher1", "password": "wrong"}).encode(),
        )
        self.assertEqual(status, 401)

    def test_malformed_session_token_is_rejected(self):
        self.assertIsNone(app_module._get_session_username("é.invalid"))


if __name__ == "__main__":
    unittest.main()