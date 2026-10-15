"""FastAPI app entrypoint (doc 05 Section 2)."""
from fastapi import FastAPI

from .routes import admin, auth, files, keys

app = FastAPI(title="SecureVault API")

API_PREFIX = "/api/v1"
app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(keys.router, prefix=API_PREFIX)
app.include_router(files.router, prefix=API_PREFIX)
app.include_router(admin.router, prefix=API_PREFIX)
