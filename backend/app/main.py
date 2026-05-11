from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import analyses, upload, users
from database.session import init_db

app = FastAPI(title="DDoS CSV API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(upload.router)
app.include_router(analyses.router)
app.include_router(users.router)


@app.on_event("startup")
def _startup() -> None:
    init_db()

