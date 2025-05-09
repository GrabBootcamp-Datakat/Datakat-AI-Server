abnormal_event_ids = ["E34", "E40", "E42", "E44", "E28", "E31"]

class Event:
    def __init__(self, event_id, template, is_abnormal=False):
        self.event_id = event_id
        self.template = template
        self.is_abnormal = is_abnormal or event_id in abnormal_event_ids