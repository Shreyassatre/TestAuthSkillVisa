import os
from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth, OAuthError
from starlette.config import Config
import secrets
from datetime import timedelta
from typing import Optional
from pymongo.collection import Collection
from auth_utils import create_access_token

router = APIRouter()

# Configuration for OAuth
config = Config()
oauth = OAuth(config)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")  # Update with your redirect URI

# Configure Google OAuth
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)

@router.get("/login/google")
async def login_via_google(request: Request):
    # Generate a secure random state for CSRF protection
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    
    # Redirect to Google login
    redirect_uri = request.url_for("auth_via_google")
    return await oauth.google.authorize_redirect(request, redirect_uri, state=state)

@router.get("/auth/google/callback")
async def auth_via_google(request: Request):
    from db import get_users_collection
    from datetime import datetime
    
    try:
        # Verify state to prevent CSRF attacks
        session_state = request.session.get("oauth_state")
        query_state = request.query_params.get("state")
        
        if not session_state or session_state != query_state:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Invalid state parameter"
            )
        
        # Get token from Google
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo")
        
        if not user_info or not user_info.get("email"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Could not fetch user information from Google"
            )
        
        # Extract user info
        email = user_info["email"]
        name = user_info.get("name", "")
        picture = user_info.get("picture", "")
        
        # Check if user exists in database, if not create a new one
        users_collection = get_users_collection()
        if users_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service unavailable"
            )
            
        user = users_collection.find_one({"email": email})
        
        if not user:
            # Create new user
            user_data = {
                "email": email,
                "name": name,
                "picture": picture,
                "role": "user",  # Default role
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow()
            }
            users_collection.insert_one(user_data)
        else:
            # Update last login time
            users_collection.update_one(
                {"email": email},
                {"$set": {"last_login": datetime.utcnow()}}
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=30)
        access_token = create_access_token(
            data={"sub": email}, expires_delta=access_token_expires
        )
        
        # Redirect to frontend with token
        # (In a real app, you might want to handle this differently)
        redirect_url = f"/auth-success?token={access_token}"
        return RedirectResponse(url=redirect_url)
        
    except OAuthError as error:
        return RedirectResponse(url=f"/auth-error?error={error.error}")
    except Exception as e:
        return RedirectResponse(url=f"/auth-error?error=Unknown error: {str(e)}")