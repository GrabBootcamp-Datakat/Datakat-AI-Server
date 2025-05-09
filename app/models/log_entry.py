class LogEntry:
    def __init__(self, id, timestamp, level, component, content, application, source_file, raw_log, event_id=None, is_anomaly=False):
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
