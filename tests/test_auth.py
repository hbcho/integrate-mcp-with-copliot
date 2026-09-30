import json
import os
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

import jwt
import pyotp
from fastapi.testclient import TestClient

from src.app import DEFAULT_INSTITUTION_ID, activities, app
from src.auth import Role, TOKEN_ISSUER, User, create_access_token, password_hasher


class AuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "correct-horse-battery-staple"
        password_hash = password_hasher.hash(cls.password)
        cls.mfa_secrets = {
            role.value: pyotp.random_base32()
            for role in Role
            if role != Role.GUARDIAN
        }
        cls.users = [
            {
                "username": role.value,
                "password_hash": password_hash,
                "role": role.value,
                "institution_id": DEFAULT_INSTITUTION_ID,
                "mfa_secret": cls.mfa_secrets.get(role.value),
            }
            for role in Role
        ]

    def setUp(self):
        self.client = TestClient(app)
        self.environment = patch.dict(os.environ, {
            "JWT_SECRET_KEY": "test-secret-key-that-is-at-least-32-bytes-long",
            "AUTH_USERS_JSON": json.dumps(self.users),
        })
        self.environment.start()
        self.original_activities = deepcopy(activities)
        activities["Other School Activity"] = {
            "description": "Private activity",
            "schedule": "Mondays",
            "max_participants": 10,
            "participants": [],
            "institution_id": "another-school",
        }

    def tearDown(self):
        activities.clear()
        activities.update(self.original_activities)
        self.environment.stop()

    def token_for(self, role, institution_id=DEFAULT_INSTITUTION_ID):
        user = User(
            username=role.value,
            password_hash="unused",
            role=role,
            institution_id=institution_id,
        )
        return create_access_token(user)

    def headers_for(self, role, institution_id=DEFAULT_INSTITUTION_ID):
        return {"Authorization": f"Bearer {self.token_for(role, institution_id)}"}

    def login(self, role, otp_code=None):
        if role != Role.GUARDIAN and otp_code is None:
            otp_code = pyotp.TOTP(self.mfa_secrets[role.value]).now()
        return self.client.post("/auth/token", json={
            "username": role.value,
            "password": self.password,
            "otp_code": otp_code,
        })

    def test_missing_token_returns_structured_unauthorized(self):
        response = self.client.get("/activities")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "UNAUTHORIZED")

    def test_login_returns_access_token(self):
        response = self.login(Role.TEACHER)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"]["role"], Role.TEACHER.value)
        self.assertTrue(response.json()["access_token"])
        self.assertIn("refresh_token", response.headers["set-cookie"])

    def test_privileged_login_requires_mfa(self):
        response = self.login(Role.TEACHER, otp_code="invalid")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "INVALID_CREDENTIALS")

    def test_refresh_tokens_rotate_and_cannot_be_reused(self):
        login_response = self.login(Role.GUARDIAN)
        original_refresh_token = login_response.cookies["refresh_token"]
        self.client.cookies.set("refresh_token", original_refresh_token, path="/auth")

        refresh_response = self.client.post("/auth/refresh")
        self.client.cookies.set("refresh_token", original_refresh_token, path="/auth")
        replay_response = self.client.post("/auth/refresh")

        self.assertEqual(refresh_response.status_code, 200)
        self.assertEqual(replay_response.status_code, 401)

    def test_logout_revokes_access_and_refresh_tokens(self):
        login_response = self.login(Role.GUARDIAN)
        access_token = login_response.json()["access_token"]
        refresh_token = login_response.cookies["refresh_token"]
        self.client.cookies.set("refresh_token", refresh_token, path="/auth")
        logout_response = self.client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        access_response = self.client.get(
            "/activities", headers={"Authorization": f"Bearer {access_token}"}
        )
        self.client.cookies.set("refresh_token", refresh_token, path="/auth")
        refresh_response = self.client.post("/auth/refresh")

        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(access_response.status_code, 401)
        self.assertEqual(refresh_response.status_code, 401)

    def test_guardian_can_read_but_cannot_change_enrollment(self):
        headers = self.headers_for(Role.GUARDIAN)

        self.assertEqual(self.client.get("/activities", headers=headers).status_code, 200)
        response = self.client.post(
            "/activities/Chess Club/signup",
            params={"email": "new-student@mergington.edu"},
            headers=headers,
        )

        self.assertEqual(response.status_code, 403)

    def test_teacher_can_enroll_but_cannot_change_capacity(self):
        headers = self.headers_for(Role.TEACHER)
        signup = self.client.post(
            "/activities/Chess Club/signup",
            params={"email": "new-student@mergington.edu"},
            headers=headers,
        )
        capacity = self.client.patch(
            "/activities/Chess Club/capacity",
            json={"max_participants": 20},
            headers=headers,
        )

        self.assertEqual(signup.status_code, 200)
        self.assertEqual(capacity.status_code, 403)

    def test_admin_can_change_capacity(self):
        response = self.client.patch(
            "/activities/Chess Club/capacity",
            json={"max_participants": 20},
            headers=self.headers_for(Role.ADMIN),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(activities["Chess Club"]["max_participants"], 20)

    def test_activities_are_scoped_to_user_institution(self):
        response = self.client.get("/activities", headers=self.headers_for(Role.GUARDIAN))
        cross_institution = self.client.post(
            "/activities/Other School Activity/signup",
            params={"email": "new-student@mergington.edu"},
            headers=self.headers_for(Role.TEACHER),
        )

        self.assertNotIn("Other School Activity", response.json())
        self.assertEqual(cross_institution.status_code, 404)

    def test_expired_token_returns_same_unauthorized_code(self):
        token = jwt.encode({
            "sub": "guardian",
            "role": Role.GUARDIAN.value,
            "institution_id": DEFAULT_INSTITUTION_ID,
            "iss": TOKEN_ISSUER,
            "token_type": "access",
            "jti": "expired-test-token",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
        }, os.environ["JWT_SECRET_KEY"], algorithm="HS256")
        response = self.client.get("/activities", headers={"Authorization": f"Bearer {token}"})

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "UNAUTHORIZED")


if __name__ == "__main__":
    unittest.main()
