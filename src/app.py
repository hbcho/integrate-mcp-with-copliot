"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
import os
from pathlib import Path

from src.auth import (
    ACCESS_TOKEN_MINUTES,
    LoginRequest,
    Role,
    TokenResponse,
    UserInfo,
    authenticate_user,
    bearer_scheme,
    clear_refresh_cookie,
    create_token_pair,
    get_current_user,
    revoke_access_token,
    revoke_refresh_token,
    require_roles,
    rotate_refresh_token,
    set_refresh_cookie,
)

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}

DEFAULT_INSTITUTION_ID = "mergington-high-school"
for activity in activities.values():
    activity["institution_id"] = DEFAULT_INSTITUTION_ID


class CapacityUpdate(BaseModel):
    max_participants: int = Field(gt=0)


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.post("/auth/token", response_model=TokenResponse)
def login(request: LoginRequest, response: Response):
    user = authenticate_user(request.username, request.password, request.otp_code)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "INVALID_CREDENTIALS", "message": "Username or password is incorrect."},
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token, refresh_token = create_token_pair(user)
    set_refresh_cookie(response, refresh_token)
    return TokenResponse(
        access_token=access_token,
        expires_in=ACCESS_TOKEN_MINUTES * 60,
        user=UserInfo(
            username=user.username,
            role=user.role,
            institution_id=user.institution_id,
        ),
    )


@app.post("/auth/refresh", response_model=TokenResponse)
def refresh_session(request: Request, response: Response):
    access_token, refresh_token, user = rotate_refresh_token(
        request.cookies.get("refresh_token", "")
    )
    set_refresh_cookie(response, refresh_token)
    return TokenResponse(
        access_token=access_token,
        expires_in=ACCESS_TOKEN_MINUTES * 60,
        user=user,
    )


@app.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    user: UserInfo = Depends(get_current_user),
):
    if credentials is not None:
        revoke_access_token(credentials.credentials)
    revoke_refresh_token(request.cookies.get("refresh_token"))
    clear_refresh_cookie(response)
    return {"message": "Signed out"}


@app.get("/activities")
def get_activities(user: UserInfo = Depends(get_current_user)):
    return {
        name: {key: value for key, value in activity.items() if key != "institution_id"}
        for name, activity in activities.items()
        if activity["institution_id"] == user.institution_id
    }


def get_accessible_activity(activity_name: str, user: UserInfo) -> dict:
    activity = activities.get(activity_name)
    if activity is None or activity["institution_id"] != user.institution_id:
        raise HTTPException(status_code=404, detail="Activity not found")
    return activity


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    user: UserInfo = Depends(require_roles(Role.TEACHER, Role.ADMIN)),
):
    """Sign up a student for an activity"""
    activity = get_accessible_activity(activity_name, user)

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    user: UserInfo = Depends(require_roles(Role.TEACHER, Role.ADMIN)),
):
    """Unregister a student from an activity"""
    activity = get_accessible_activity(activity_name, user)

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}


@app.patch("/activities/{activity_name}/capacity")
def update_activity_capacity(
    activity_name: str,
    update: CapacityUpdate,
    user: UserInfo = Depends(require_roles(Role.ADMIN)),
):
    activity = get_accessible_activity(activity_name, user)
    if update.max_participants < len(activity["participants"]):
        raise HTTPException(
            status_code=409,
            detail={"code": "CAPACITY_BELOW_ENROLLMENT", "message": "Capacity cannot be lower than current enrollment."},
        )
    activity["max_participants"] = update.max_participants
    return {"message": f"Capacity updated for {activity_name}"}
