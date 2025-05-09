# Observability AI Platform

This is a FastAPI-based observability platform that provides AI-powered monitoring and analysis capabilities.

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Make (optional, for using Makefile commands)

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd Datakat-AI-Server
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

3. Install dependencies:

Using Makefile:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Running the Application

```bash
uvicorn app.main:app --host localhost --port 8000
```

The application will be available at `http://localhost:8000`

## Environment Variables

Create a `.env` file in the root directory with the following variables (if required):

```
# Add your environment variables here
```

## Features

- FastAPI-based REST API
- Elasticsearch integration
- Machine learning capabilities (scikit-learn)
- Real-time monitoring
- Data analysis tools

## Dependencies

Key dependencies include:

- FastAPI
- Elasticsearch
- scikit-learn
- APScheduler
- Python-dotenv

For a complete list of dependencies, see `requirements.txt`
