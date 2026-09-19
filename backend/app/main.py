"""OwLance Backend — FastAPI application entrypoint."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.session import init_db
from app.routers import (
    consent_router,
    scan_router,
    optimizer_router,
    connectors_router,
    auth_router,
    analytics_router,
    whatsapp_router,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

def _seed_demo_user() -> None:
    """
    Ensure a working account exists on a fresh database.

    Without this a new clone has no way in: registration is open, but a
    reviewer should not have to create an account to see the product.
    """
    from app.db.models import User
    from app.db.session import SessionLocal
    from app.services.auth import hash_password

    db = SessionLocal()
    try:
        email = settings.DEMO_EMAIL.strip().lower()
        if db.query(User).filter(User.email == email).first():
            return
        db.add(User(
            email=email,
            password_hash=hash_password(settings.DEMO_PASSWORD),
            org_name="OwLance Demo Org",
        ))
        db.commit()
        logger.info("Seeded demo account %s", email)
    except Exception:
        logger.exception("Could not seed the demo account")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Create tables on boot so a fresh clone runs with zero setup."""
    init_db()
    if settings.SEED_DEMO_USER:
        _seed_demo_user()
    logger.info("%s v%s ready", settings.PROJECT_NAME, settings.VERSION)
    yield


app = FastAPI(
    lifespan=lifespan,
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Continuous cyber risk quantification and security investment "
        "optimization. Passive attack-surface discovery, composite risk "
        "scoring (EPSS x CVSS x CWE x Exposure x Criticality), and a "
        "greedy-ratio knapsack budget optimizer."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(consent_router)
app.include_router(scan_router)
app.include_router(optimizer_router)
app.include_router(auth_router)
app.include_router(connectors_router)
app.include_router(analytics_router)
app.include_router(whatsapp_router)


@app.get("/", tags=["Health"], summary="Service metadata")
def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "ok",
        "docs": "/docs",
        "endpoints": [
            "POST /consent",
            "GET /scan/{domain}",
            "POST /optimize",
            "POST /connectors/{source_id}",
            "POST /auth/login",
            "GET /history",
            "GET /audit/verify",
            "POST /whatsapp/send-passport",
        ],
    }


@app.get("/health", tags=["Health"], summary="Liveness probe")
def health():
    return {"status": "healthy"}
