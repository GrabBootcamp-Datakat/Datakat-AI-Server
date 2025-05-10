from app.models.alert_config import AlertConfig
from app.config.config import config as app_config
from elasticsearch import Elasticsearch
import json
from datetime import datetime, timezone

class AlertConfigService:
    def __init__(self):
        self.es = Elasticsearch(
            app_config.ELASTICSEARCH_ADDRESSES,
            headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8"}
        )
        self.index_name = "alert_config"
        self._ensure_index_exists()
        self._ensure_default_config()

    def _ensure_index_exists(self):
        """Ensure alert config index exists"""
        if not self.es.indices.exists(index=self.index_name):
            self.es.indices.create(
                index=self.index_name,
                body={
                    "mappings": {
                        "properties": {
                            "window_hours": {"type": "integer"},
                            "threshold": {"type": "integer"},
                            "levels": {"type": "keyword"},
                            "cooldown_seconds": {"type": "integer"},
                            "slack_webhook_url": {"type": "keyword"},
                            "last_alert_time": {"type": "date"}
                        }
                    }
                }
            )

    def _ensure_default_config(self):
        """Ensure default config exists"""
        try:
            self.es.get(index=self.index_name, id="latest")
        except Exception:
            default_config = AlertConfig(
                window_hours=app_config.ANOMALY_ALERT_WINDOW_HOURS,
                threshold=app_config.ANOMALY_ALERT_THRESHOLD,
                levels=app_config.ANOMALY_ALERT_LEVELS,
                cooldown_seconds=app_config.ANOMALY_ALERT_COOLDOWN_SECONDS,
                slack_webhook_url=app_config.SLACK_WEBHOOK_URL,
                last_alert_time=None
            )
            self.update_config(default_config)
            print("Created default alert config")

    def get_config(self) -> AlertConfig:
        """Get current alert configuration"""
        try:
            response = self.es.get(
                index=self.index_name,
                id="latest"
            )
            if response["found"]:
                source = response["_source"]
                if source.get("last_alert_time"):
                    # Parse ISO format string to datetime with UTC timezone
                    try:
                        last_alert_time = datetime.fromisoformat(source["last_alert_time"].replace("Z", "+00:00"))
                        if not last_alert_time.tzinfo:
                            last_alert_time = last_alert_time.replace(tzinfo=timezone.utc)
                        source["last_alert_time"] = last_alert_time
                    except Exception as e:
                        print(f"Error parsing last_alert_time: {str(e)}")
                        source["last_alert_time"] = None
                alert_config = AlertConfig(**source)
                print(f"Using saved alert config: {alert_config.dict()}")
                return alert_config
        except Exception as e:
            print(f"Error getting alert config: {str(e)}")
            # Return default config on error
            default_config = AlertConfig(
                window_hours=app_config.ANOMALY_ALERT_WINDOW_HOURS,
                threshold=app_config.ANOMALY_ALERT_THRESHOLD,
                levels=app_config.ANOMALY_ALERT_LEVELS,
                cooldown_seconds=app_config.ANOMALY_ALERT_COOLDOWN_SECONDS,
                slack_webhook_url=app_config.SLACK_WEBHOOK_URL,
                last_alert_time=None
            )
            print(f"Using default alert config on error: {default_config.dict()}")
            return default_config

    def update_config(self, alert_config: AlertConfig) -> bool:
        """Update alert configuration"""
        try:
            config_dict = alert_config.dict()
            if config_dict.get("last_alert_time"):
                config_dict["last_alert_time"] = config_dict["last_alert_time"].isoformat()
            self.es.index(
                index=self.index_name,
                body=config_dict,
                id="latest"
            )
            print(f"Updated alert config: {alert_config.dict()}")
            return True
        except Exception as e:
            print(f"Error updating alert config: {str(e)}")
            return False

    def update_last_alert_time(self, last_alert_time: datetime) -> bool:
        """Update last alert time"""
        try:
            if not last_alert_time.tzinfo:
                last_alert_time = last_alert_time.replace(tzinfo=timezone.utc)
            self.es.update(
                index=self.index_name,
                id="latest",
                body={
                    "doc": {
                        "last_alert_time": last_alert_time.isoformat()
                    }
                }
            )
            print(f"Updated last alert time to: {last_alert_time.isoformat()}")
            return True
        except Exception as e:
            print(f"Error updating last alert time: {str(e)}")
            return False 