from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes.analyze import router as analyze_router
from app.api.routes.adversarial import router as adversarial_router
from app.api.routes.history import router as history_router
from app.database.connection import init_db

app = FastAPI(
    title="PhishTrace AI API",
    description="Explainable multi-signal phishing URL investigation, threat relationship graph, and adversarial testing platform.",
    version="0.6.0",
)

@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception as exc:
        print(f"Database initialization warning: {exc}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(adversarial_router)
app.include_router(history_router)


@app.get("/api/v1/health")
def health_check():
    return {"status": "ok", "env": settings.app_env, "version": "0.6.0"}
