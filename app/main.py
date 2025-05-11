from app.scheduler import AnomalyDetectionScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.services.anomaly_api import router as anomaly_router
from app.services.alert_api import router as alert_router

scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Lifespan starting...")
    anomaly_detection_scheduler = AnomalyDetectionScheduler()
    scheduler.add_job(anomaly_detection_scheduler.run, "interval", seconds=10)
    scheduler.start()
    print("Scheduler started!")
    yield
    print("Shutting down scheduler...")
    scheduler.shutdown()

app = FastAPI(lifespan=lifespan)

# --- BEGIN CORS CONFIGURATION ---
origins = [
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  
    allow_credentials=True,
    allow_methods=["*"],   
    allow_headers=["*"],    
)

app.include_router(anomaly_router, prefix="/api/v1", tags=["anomalies"])
app.include_router(alert_router, prefix="/api/v1")

@app.get("/")
def root():
    return {"message": "Elastic log fetcher with anomaly detection is running"}
