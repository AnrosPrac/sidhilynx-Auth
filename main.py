from fastapi import FastAPI
from auth.api.v1.users import router as auth_router

app = FastAPI(title="CLG Project")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    auth_router,
    prefix="/api/v1/auth",
    tags=["Auth"]
)

@app.get("/health")
def health():
    return {"ok": True}
