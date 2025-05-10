from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class AlertConfig(BaseModel):
    window_hours: int
    threshold: int
    levels: List[str]
    cooldown_seconds: int
    slack_webhook_url: str
    last_alert_time: Optional[datetime] = None 