from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    def __init__(self):
        # elasticsearch
        self.ELASTICSEARCH_ADDRESSES = os.getenv("ELASTICSEARCH_ADDRESSES")
        self.ELASTICSEARCH_LOG_INDEX = os.getenv("ELASTICSEARCH_LOG_INDEX")
        self.ELASTICSEARCH_EVENT_INDEX = os.getenv("ELASTICSEARCH_EVENT_INDEX")

        # event templates
        self.EVENT_TEMPLATES_FILE = os.getenv("EVENT_TEMPLATES_FILE")

config = Config()