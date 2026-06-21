import os

from fastapi import FastAPI, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from rate_limit import limiter
from api.v1.users import router as auth_router
from api.v1.admin_clients import router as admin_clients_router


app = FastAPI(title="CLG Project")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

from fastapi.middleware.cors import CORSMiddleware

_allowed_origin_regex = os.getenv(
    "ALLOWED_ORIGIN_REGEX",
    r"^https?://([a-zA-Z0-9-]+\.)*sidhi\.xyz$"
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=_allowed_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


app.include_router(admin_clients_router)

app.include_router(
    auth_router,
    prefix="/api/v1/auth",
    tags=["Auth"]
)

@app.get("/health")
def health():
    return {"ok": True}
