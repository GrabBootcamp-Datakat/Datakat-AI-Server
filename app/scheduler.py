from app.models.event import Event
from app.services.elastic import ElasticService
from app.services.anomaly import AnomalyService
from app.services.clustering import ClusteringService
from typing import List
import csv

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
        self.event_templates = self.elastic_service.get_events()

    def run(self):
        try:
            print("Fetching logs from Elasticsearch...")
            logs, index_name = self.elastic_service.get_logs()
            unknown_logs = self.anomaly_service.check_anomaly(logs, self.event_templates)
            new_templates = self.clustering_service.cluster_and_generate_templates(unknown_logs, self.event_templates)
            self.elastic_service.save_logs(logs, index_name)

            # update event templates
            diff_templates = new_templates[len(self.event_templates):]
            self.event_templates.extend(diff_templates)
            self.elastic_service.save_new_events(diff_templates)

        except Exception as e:
            print(f"Error running anomaly detection scheduler: {str(e)}")
            if hasattr(e, 'info'):
                print(f"Error details: {e.info}")