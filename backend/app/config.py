"""Application Configuration using Pydantic Settings"""
import secrets
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    PROJECT_NAME: str = "OwLance Backend"
    VERSION: str = "0.1.0"
    API_PREFIX: str = ""

    # Database. SQLite by default so a fresh clone runs with zero setup.
    # Set DATABASE_URL to a postgresql+psycopg2://... URL in .env to use
    # PostgreSQL; session.py falls back to SQLite automatically if that
    # server is unreachable.
    DATABASE_URL: str = "sqlite:///./owlance.db"
    SQLITE_FALLBACK_URL: str = "sqlite:///./owlance.db"

    # CORS origins
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # External APIs
    CRT_SH_URL: str = "https://crt.sh"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    OSV_API_URL: str = "https://api.osv.dev/v1/vulns"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # --- Authentication ---------------------------------------------
    # SECRET_KEY signs session tokens. The default below is for local
    # development only: it is regenerated on every boot, so restarting the
    # server invalidates existing sessions. Set a fixed SECRET_KEY in .env
    # for any deployment where that matters.
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12  # 12 hours

    # Seeded on first boot so the platform is reachable out of the box.
    # Change or remove these before exposing the service publicly.
    DEMO_EMAIL: str = "demo@owlance.in"
    DEMO_PASSWORD: str = "owlance2026"
    SEED_DEMO_USER: bool = True

    # Cache TTL and Timeouts
    CACHE_TTL_HOURS: int = 24
    REQUEST_TIMEOUT: float = 10.0

    # --- WhatsApp delivery (Twilio) ----------------------------------
    # Fill these in .env, never here -- .env is gitignored, this file is not.
    # With all three blank the WhatsApp endpoint still works: it composes the
    # real message and returns it as a preview marked delivered=false, so the
    # UI can demo the exact text without a live account behind it.
    #
    #   TWILIO_ACCOUNT_SID    Console home, starts "AC..."
    #   TWILIO_AUTH_TOKEN     Console home, next to the SID (secret)
    #   TWILIO_WHATSAPP_FROM  The sender in E.164, e.g. "+14155238886" for the
    #                         Twilio sandbox, or your own approved number.
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_WHATSAPP_FROM: str = ""
    TWILIO_API_BASE: str = "https://api.twilio.com/2010-04-01"

    # Optional: send an approved WhatsApp *template* instead of free text.
    #
    # Twilio trial accounts, and any conversation whose 24-hour window has
    # closed, may only send approved templates. Set TWILIO_CONTENT_SID to the
    # template's "HX..." SID (Console > Messaging > Content Template Builder)
    # and the request carries ContentSid + ContentVariables instead of Body.
    # Leave it blank to send the full free-text passport (works for a
    # recipient who has joined the sandbox / messaged you in the last 24h).
    TWILIO_CONTENT_SID: str = ""
    # JSON map of template placeholder -> text. {domain}, {score}, {band},
    # {confidence}, {as_of} and {passport_url} are filled from the snapshot.
    # Adjust the keys/count to match your template's {{1}}, {{2}}, ... slots.
    TWILIO_CONTENT_VARIABLES: str = (
        '{"1": "{domain}", "2": "{score}/900 ({band})", "3": "{passport_url}"}'
    )

    # Country code applied to a bare national number typed without one.
    DEFAULT_PHONE_COUNTRY_CODE: str = "+91"

    # Base for the shareable passport link embedded in the message.
    PASSPORT_BASE_URL: str = "https://owlance.in/p"

    # --- Scan bounds -------------------------------------------------
    # crt.sh routinely returns hundreds of hostnames for a real domain.
    # Resolving all of them sequentially makes /scan take minutes, so the
    # target list is prioritised and capped, resolved in parallel, and the
    # whole scan is held to a wall-clock deadline. The endpoint therefore
    # always returns, with partial results rather than a hang.
    MAX_SCAN_TARGETS: int = 25
    DNS_WORKERS: int = 12
    DNS_TIMEOUT: float = 2.0
    DNS_LIFETIME: float = 4.0
    SCAN_DEADLINE_SECONDS: float = 45.0

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
