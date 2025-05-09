class LogEntry:
    def __init__(self, id, timestamp, level, component, content, application, source_file, raw_log, event_id=None, is_anomaly=False,llm_analysis: dict = None):
        self.id = id
        self.timestamp = timestamp
        self.level = level
        self.component = component
        self.content = content
        self.application = application
        self.source_file = source_file
        self.raw_log = raw_log
        self.event_id = event_id
        self.is_anomaly = is_anomaly
        self.llm_analysis = llm_analysis
    def to_dict(self):
        data = {
            "@timestamp": self.timestamp,
            "level": self.level,
            "component": self.component,
            "content": self.content,
            "application": self.application,
            "source_file": self.source_file,
            "raw_log": self.raw_log,
            "event_id": self.event_id,
            "is_anomaly": self.is_anomaly,
        }
        if self.llm_analysis: 
            data["llm_analysis"] = self.llm_analysis
        return data

