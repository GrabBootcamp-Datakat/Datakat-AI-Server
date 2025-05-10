from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    def __init__(self):
        # elasticsearch
        self.ELASTICSEARCH_ADDRESSES = os.getenv("ELASTICSEARCH_ADDRESSES")
        self.ELASTICSEARCH_LOG_INDEX = os.getenv("ELASTICSEARCH_LOG_INDEX")
        self.ELASTICSEARCH_EVENT_INDEX = os.getenv("ELASTICSEARCH_EVENT_INDEX")

        # event templates
        self.EVENT_TEMPLATES_FILE = os.getenv("EVENT_TEMPLATES_FILE")

        # LLM Configuration
        self.GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") 
        self.LLM_MODEL_NAME = os.getenv("LLM_MODEL_NAME", "gemini-1.5-flash-latest") 

        # Anomaly alert config
        self.ANOMALY_ALERT_WINDOW_HOURS = int(os.getenv("ANOMALY_ALERT_WINDOW_HOURS", "2"))
        self.ANOMALY_ALERT_THRESHOLD = int(os.getenv("ANOMALY_ALERT_THRESHOLD", "500"))
        self.ANOMALY_ALERT_LEVELS = os.getenv("ANOMALY_ALERT_LEVELS", "ERROR,WARN").split(",")
        self.ANOMALY_ALERT_COOLDOWN_SECONDS = int(os.getenv("ANOMALY_ALERT_COOLDOWN_SECONDS", "3600"))
        self.SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

config = Config()