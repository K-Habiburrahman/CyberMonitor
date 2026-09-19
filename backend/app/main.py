from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.events import router as events_router
from .api.alerts import router as alerts_router
from .api.statistics import router as statistics_router
from .api.ports import router as ports_router
from .api.threats import router as threats_router

app = FastAPI(
    title="CyberMonitor API",
    description="Security monitoring backend",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROUTERS
# ============================================================

app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(statistics_router)
app.include_router(ports_router)
app.include_router(threats_router)

# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "name": "CyberMonitor API",
        "status": "running",
        "version": "1.0.0"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# ============================================================
# AGENT STATUS
# ============================================================

@app.get("/status")
def status():

    return {
        "agent": "ACTIVE",
        "process_monitoring": "ACTIVE",
        "network_monitoring": "ACTIVE",
        "file_monitoring": "ACTIVE",
        "port_scanning": "ACTIVE",
        "database": "CONNECTED"
    }
