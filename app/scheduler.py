from app.models.event import Event
from app.services.elastic import ElasticService
from app.services.anomaly import AnomalyService
from app.services.clustering import ClusteringService
from app.services.alert_config_service import AlertConfigService
from typing import List
import csv
from datetime import datetime, timedelta, timezone
import requests
from app.config.config import config
import json

abnormal_event_ids = ["E34", "E40", "E42", "E44", "E28", "E31"]

def load_event_templates_from_csv(file_path: str) -> List[Event]:
    event_templates = []

    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            is_abnormal = row['event_id'] in abnormal_event_ids
            event_templates.append(Event(row['event_id'], row['template'], is_abnormal))

    return event_templates

class AnomalyDetectionScheduler:
    def __init__(self):
        # self.event_templates = load_event_templates_from_csv("event_templates.csv")
        # self.event_templates = self.event_templates[:50]
        self.elastic_service = ElasticService()
        self.anomaly_service = AnomalyService()
        self.clustering_service = ClusteringService()
        self.alert_config_service = AlertConfigService()
        self.event_templates = self.elastic_service.get_events()

    def check_anomaly_threshold(self):
        """Check if anomaly count exceeds threshold in recent time window"""
        try:
            alert_config = self.alert_config_service.get_config()
            
            now = datetime.now(timezone.utc)
            window_start = now - timedelta(hours=alert_config.window_hours)
            
            print(f"Checking anomalies from {window_start.isoformat()} to {now.isoformat()}")
            print(f"Alert config: threshold={alert_config.threshold}, levels={alert_config.levels}")
            
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"is_anomaly": True}},
                            {"range": {
                                "detection_timestamp": {
                                    "gte": window_start.isoformat(),
                                    "lte": now.isoformat()
                                }
                            }},
                            {"terms": {"level.keyword": alert_config.levels}}
                        ]
                    }
                }
            }

            print(f"Elasticsearch query: {json.dumps(query, indent=2)}")

            response = self.elastic_service.es.count(
                index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
                body=query
            )

            anomaly_count = response['count']
            print(f"Found {anomaly_count} anomalies in time window")
            
            last_alert_time = alert_config.last_alert_time
            if last_alert_time:
                if not last_alert_time.tzinfo:
                    last_alert_time = last_alert_time.replace(tzinfo=timezone.utc)
                time_since_last_alert = (now - last_alert_time).total_seconds()
                print(f"Last alert time: {last_alert_time.isoformat()}")
            else:
                time_since_last_alert = float('inf')
                print("No previous alert")
            print(f"Time since last alert: {time_since_last_alert}s (cooldown: {alert_config.cooldown_seconds}s)")
            
            if anomaly_count >= alert_config.threshold:
                print(f"Anomaly count {anomaly_count} exceeds threshold {alert_config.threshold}")
                if time_since_last_alert >= alert_config.cooldown_seconds:
                    print("Cooldown period passed, sending alert...")
                    # Send Slack alert
                    message = {
                        "text": f"⚠️ *Anomaly Alert*\n"
                               f"Found {anomaly_count} anomalies in the last {alert_config.window_hours} hours\n"
                               f"Threshold: {alert_config.threshold}\n"
                               f"Levels: {', '.join(alert_config.levels)}"
                    }
                    
                    print(f"Sending Slack message: {json.dumps(message, indent=2)}")
                    response = requests.post(
                        alert_config.slack_webhook_url,
                        json=message
                    )
                    
                    if response.status_code == 200:
                        self.alert_config_service.update_last_alert_time(now)
                        print(f"Successfully sent anomaly alert to Slack. Count: {anomaly_count}")
                    else:
                        print(f"Failed to send Slack alert. Status code: {response.status_code}")
                        print(f"Response text: {response.text}")
                else:
                    print("Still in cooldown period, skipping alert")
            else:
                print(f"Anomaly count {anomaly_count} is below threshold {alert_config.threshold}")

        except Exception as e:
            print(f"Error checking anomaly threshold: {str(e)}")
            if hasattr(e, 'info'):
                print(f"Error details: {e.info}")

    def run(self):
        try:
            print("Fetching logs from Elasticsearch...")
            logs, index_name = self.elastic_service.get_logs()
            
            current_time = datetime.now(timezone.utc).isoformat()
            for log in logs:
                log.detection_timestamp = current_time
                
            unknown_logs = self.anomaly_service.check_anomaly(logs, self.event_templates)
            new_templates = self.clustering_service.cluster_and_generate_templates(unknown_logs, self.event_templates)
            self.elastic_service.save_logs(logs, index_name)

            diff_templates = new_templates[len(self.event_templates):]
            self.event_templates.extend(diff_templates)
            self.elastic_service.save_new_events(diff_templates)

            self.check_anomaly_threshold()

        except Exception as e:
            print(f"Error running anomaly detection scheduler: {str(e)}")
            if hasattr(e, 'info'):
                print(f"Error details: {e.info}")