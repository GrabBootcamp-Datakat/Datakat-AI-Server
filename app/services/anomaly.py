from app.models.log_entry import LogEntry
from app.models.event import Event
from typing import List
import re


class AnomalyService:
    def __init__(self):
        self.compiled_patterns = {}

    # compile template to regex pattern
    def _get_pattern(self, template: str) -> re.Pattern:
        if template not in self.compiled_patterns:
            pattern = re.escape(template).replace(re.escape('<*>'), r'([^ ]+)')
            self.compiled_patterns[template] = re.compile(pattern)
        return self.compiled_patterns[template]

    def check_anomaly(self, logs: List[LogEntry], event_templates: List[Event]) -> List[LogEntry]:
        unknown_logs = []

        for log in logs:
            log_content = log.content
            matched = False

            for event in event_templates:
                pattern = self._get_pattern(event.template)
                if pattern.match(log_content):
                    log.event_id = event.event_id
                    log.is_anomaly = event.is_abnormal
                    matched = True
                    break

            if not matched:
                log.is_anomaly = True
                unknown_logs.append(log)

        return unknown_logs