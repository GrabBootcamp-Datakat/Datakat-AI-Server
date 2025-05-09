from typing import List, Tuple
import re

class PreprocessService:
    def __init__(self):
        self.patterns = [
            (r'\d{4}-\d{2}-\d{2}', '<DATE>'),                                           # 2025-05-08
            (r'\d{2}-\d{2}-\d{2}', '<DATE>'),                                           # 05-08-25
            (r'\d{2}/[a-z]{3}/\d{4}', '<DATE>'),                                        # 08/May/2025
            (r'\d{2}:\d{2}:\d{2}', '<TIME>'),                                           # 12:34:56
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '<IP>'),                             # IP address
            (r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '<ID>'),  # UUID
            (r'\b[a-z0-9._-]*mesos[-_]slave[-_]*\d+\b', '<HOST>'),                      # mesos-slave-XX
            (r'\b[a-z0-9._-]*node[-_]*\d+\b', '<HOST>'),                                # node-123
            (r'/(?:[\w.-]+/)*[\w.-]+', '<PATH>'),                                       # Unix-style paths
            (r'\d+\.\d+', '<NUM>'),                                                     # Decimal numbers
            (r'\d+', '<NUM>'),                                                          # Integers
        ]

        self.patterns_reverse = [
            (r'\d{4}-\d{2}-\d{2}', '<*>'),                                           # 2025-05-08
            (r'\d{2}-\d{2}-\d{2}', '<*>'),                                           # 05-08-25
            (r'\d{2}/[a-z]{3}/\d{4}', '<*>'),                                        # 08/May/2025
            (r'\d{2}:\d{2}:\d{2}', '<*>'),                                           # 12:34:56
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '<*>'),                             # IP address
            (r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '<*>'),  # UUID
            (r'\b[a-z0-9._-]*mesos[-_]slave[-_]*\d+\b', '<*>'),                      # mesos-slave-XX
            (r'\b[a-z0-9._-]*node[-_]*\d+\b', '<*>'),                                # node-123
            (r'/(?:[\w.-]+/)*[\w.-]+', '<*>'),                                       # Unix-style paths
            (r'\d+\.\d+', '<*>'),                                                     # Decimal numbers
            (r'\d+', '<*>'),                                                          # Integers
        ]

    def normalize_log(self, log_text: str) -> str:
        log_text = log_text.lower()
        for pattern, replacement in self.patterns:
            log_text = re.sub(pattern, replacement, log_text)
        return log_text
    
    def normalize_log_template(self, log_text: str) -> str:
        log_text = log_text.lower()
        for pattern, replacement in self.patterns_reverse:
            log_text = re.sub(pattern, replacement, log_text)
        return log_text

    def normalize_template(self, template: str) -> str:
        return re.sub(r"<\*>", "*", template, flags=re.IGNORECASE).strip()
