"""Routers Package"""
from app.routers.consent import router as consent_router
from app.routers.scan import router as scan_router
from app.routers.optimizer import router as optimizer_router
from app.routers.connectors import router as connectors_router
from app.routers.auth import router as auth_router
from app.routers.analytics import router as analytics_router
from app.routers.whatsapp import router as whatsapp_router

__all__ = ["consent_router", "scan_router", "optimizer_router", "connectors_router", "auth_router", "analytics_router", "whatsapp_router"]
