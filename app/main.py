from app.scheduler import AnomalyDetectionScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from contextlib import asynccontextmanager
from fastapi import FastAPI

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

@app.get("/")
def root():
    return {"message": "Elastic log fetcher with anomaly detection is running"}
