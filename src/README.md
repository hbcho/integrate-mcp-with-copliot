# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Sign up for activities

## Getting Started

1. Install the dependencies:

   ```
   pip install -r requirements.txt
   ```

2. Configure a JWT secret and users. User passwords must be Argon2 hashes; generate one with:

   ```
   python -c 'from pwdlib import PasswordHash; print(PasswordHash.recommended().hash("replace-this-password"))'
   ```

   Generate a TOTP secret for each teacher/admin with `python -c 'import pyotp; print(pyotp.random_base32())'`. Set `JWT_SECRET_KEY` to a random value of at least 32 characters and `AUTH_USERS_JSON` to a JSON array of users with `username`, `password_hash`, `role` (`guardian`, `teacher`, or `admin`), and `institution_id` fields. Teacher and admin entries must also include their MFA `mfa_secret`; guardians do not use MFA. Set `AUTH_COOKIE_SECURE=true` when serving over HTTPS.

3. Run the application from the repository root:

   ```
   uvicorn src.app:app --reload
   ```

4. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| POST   | `/auth/token`                                                     | Exchange username and password for a 20-minute access token          |
| POST   | `/auth/refresh`                                                   | Rotate the HttpOnly refresh cookie and issue a new access token       |
| POST   | `/auth/logout`                                                    | Revoke the current access and refresh tokens                          |
| GET    | `/activities`                                                     | Get activities for the authenticated user's institution             |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Teacher/admin: sign up a student                                     |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Teacher/admin: unregister a student                              |
| PATCH  | `/activities/{activity_name}/capacity`                            | Admin: update activity capacity                                      |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.

Refresh-token state and access-token revocations are also stored in process memory. Use a shared persistent store before running multiple workers or deploying across instances.

Run the authorization tests with `pip install -r requirements-dev.txt` followed by `python -m unittest discover -s tests -v`.
