from app.config.config import config
from app.models.log_entry import LogEntry
from app.models.event import Event
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from typing import List, Optional, Tuple
import time
import json
import os


class CheckpointManager:
    def __init__(self, filepath: str = 'checkpoint.json'):
        self.filepath = filepath

    def load(self) -> Optional[str]:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    checkpoint = json.load(f)
                    return checkpoint.get('last_sort_value')
            except Exception as e:
                print(f"Error loading checkpoint: {e}")
        return None

    def save(self, last_sort_value: str):
        try:
            with open(self.filepath, 'w') as f:
                json.dump({'last_sort_value': last_sort_value}, f)
        except Exception as e:
            print(f"Error saving checkpoint: {e}")

class ElasticService:
    def __init__(self):
        self.es = Elasticsearch(
            config.ELASTICSEARCH_ADDRESSES,
            headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8"}
        )
        self.checkpoint_manager = CheckpointManager()
        self.last_sort_value = self.checkpoint_manager.load() or 0
        self.last_save_time = time.time()

    def get_logs(self) -> Tuple[List[LogEntry], str]:
        try:
            body = {
                "size": 5000,
                "sort": [
                    {"@timestamp": {"order": "asc"}} 
                ],
                "query": {
                    "bool": {
                        "must": [
                            {"match_all": {}}
                        ]
                    }
                }
            }

            if self.last_sort_value:
                body["search_after"] = self.last_sort_value

            response = self.es.search(
                index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
                body=body
            )

            hits = response['hits']['hits']
            
            logs = [
                LogEntry(
                    id=hit['_id'],
                    timestamp=hit['_source'].get('@timestamp'),
                    level=hit['_source'].get('level'),
                    component=hit['_source'].get('component'),
                    content=hit['_source'].get('content'),
                    application=hit['_source'].get('application'),
                    source_file=hit['_source'].get('source_file'),
                    raw_log=hit['_source'].get('raw_log'),
                    event_id=hit['_source'].get('event_id', None),
                    is_anomaly=hit['_source'].get('is_anomaly', False)
                )
                for hit in hits
            ]

            # save checkpoint every 30 seconds
            if logs:
                new_last_sort_value = hits[-1]["sort"]
                if new_last_sort_value != self.last_sort_value:
                    self.last_sort_value = new_last_sort_value
                    now = time.time()
                    if now - self.last_save_time > 30:
                        self.checkpoint_manager.save(self.last_sort_value)
                        self.last_save_time = now

            
            return logs, [hit["_index"] for hit in hits]

        except Exception as e:
            print(f"Error fetching logs: {str(e)}")
            if hasattr(e, 'info'):
                print(f"Error details: {e.info}")
            return []
        
    def save_logs(self, logs: List[LogEntry], index_names: List[str]):
        if not logs:
            return
        
        actions = []

        for i, log in enumerate(logs):
            actions.append({
                "_op_type": "update",
                "_index": index_names[i],
                "_id": log.id,
                "doc": {
                    "event_id": log.event_id,
                    "is_anomaly": log.is_anomaly,
                },
                "doc_as_upsert": True
            })

        success, _ = bulk(self.es, actions)
        print(f"Updated {success} logs in Elasticsearch")

    def get_events(self) -> List[Event]:
        response = self.es.search(
            index=f"{config.ELASTICSEARCH_EVENT_INDEX}",
            body={
                "size": 1000, 
                "query": {
                    "match_all": {}
                }
            }
        )

        hits = response['hits']['hits']
        print(hits[0])

        events = [Event(
            event_id=hit['_source']['event_id'],
            template=hit['_source']['template'],
        ) for hit in hits]

        return events
    
    def save_new_events(self, events: List[Event]):
        if not events:
            return
        
        try:
            actions = []
            for i, event in enumerate(events):
                actions.append({
                    "_op_type": "update",
                    "_index": config.ELASTICSEARCH_EVENT_INDEX,
                    "_id": event.id,
                    "doc": {
                        "template": event.template,
                        "is_abnormal": event.is_abnormal
                    },
                    "doc_as_upsert": True
                })
            success, _ = bulk(self.es, actions)
            print(f"Updated {success} events in Elasticsearch")
        except Exception as e:
            print(f"Error saving new events: {str(e)}")
