"""FastAPI application factory."""

from fastapi import FastAPI

from app.api.routes import upload

app = FastAPI(title="DDoS CSV API", version="1.0.0")
app.include_router(upload.router)

