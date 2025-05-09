from fastapi import APIRouter, HTTPException
from typing import List, Optional
from app.services.elastic import ElasticService
from app.services.llm_analyzer import LLMAnalyzerService
from app.models.log_entry import LogEntry
from pydantic import BaseModel
import asyncio
from app.config.config import config
from datetime import datetime, timedelta

router = APIRouter()
elastic_service = ElasticService()
llm_analyzer = LLMAnalyzerService()

class AnomalyLogResponse(BaseModel):
    id: str
    timestamp: str
    level: str
    component: str
    content: str
    application: Optional[str]
    source_file: Optional[str]
    event_id: Optional[str]
    is_anomaly: bool

class PaginatedAnomalyResponse(BaseModel):
    total: int
    offset: int
    limit: int
    items: List[AnomalyLogResponse]

class LLMAnalysisRequest(BaseModel):
    log_id: str

class LLMAnalysisResponse(BaseModel):
    anomaly_detection: dict
    root_cause_analysis: dict
    recommendations: dict

@router.get("/anomalies", response_model=PaginatedAnomalyResponse)
async def get_latest_anomalies(limit: int = 10, offset: int = 0):
    """
    Get latest anomalies with optional limit and offset.
    
    Args:
        limit: Number of logs to retrieve 
        offset: Offset for pagination
    """
    try:
        count_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"is_anomaly": True}}
                    ]
                }
            }
        }

        count_response = elastic_service.es.count(
            index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
            body=count_query
        )
        total = count_response['count']

        search_query = {
            "from": offset,
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"is_anomaly": True}}
                    ]
                }
            }
        }

        response = elastic_service.es.search(
            index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
            body=search_query
        )

        hits = response['hits']['hits']
        anomalies = []
        
        for hit in hits:
            source = hit['_source']
            anomaly = AnomalyLogResponse(
                id=hit['_id'],
                timestamp=source.get('@timestamp'),
                level=source.get('level'),
                component=source.get('component'),
                content=source.get('content'),
                application=source.get('application'),
                source_file=source.get('source_file'),
                event_id=source.get('event_id'),
                is_anomaly=source.get('is_anomaly', False)
            )
            anomalies.append(anomaly)

        return PaginatedAnomalyResponse(
            total=total,
            offset=offset,
            limit=limit,
            items=anomalies
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching anomalies: {str(e)}")

@router.post("/anomalies/analyze", response_model=LLMAnalysisResponse)
async def analyze_anomaly(request: LLMAnalysisRequest):
    """
    Analyze an anomaly log entry.
    """ 
    try:
        search_response = elastic_service.es.search(
            index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
            body={
                "query": {
                    "ids": {
                        "values": [request.log_id]
                    }
                }
            }
        )

        if not search_response['hits']['hits']:
            raise HTTPException(status_code=404, detail="Log not found")

        actual_index = search_response['hits']['hits'][0]['_index']
        
        response = elastic_service.es.get(
            index=actual_index,
            id=request.log_id
        )
        
        if not response['found']:
            raise HTTPException(status_code=404, detail="Log not found")

        source = response['_source']
        log_entry = LogEntry(
            id=response['_id'],
            timestamp=source.get('@timestamp'),
            level=source.get('level'),
            component=source.get('component'),
            content=source.get('content'),
            application=source.get('application'),
            source_file=source.get('source_file'),
            raw_log=source.get('raw_log'),
            event_id=source.get('event_id'),
            is_anomaly=source.get('is_anomaly', False)
        )

        surrounding_logs = []
        try:
            log_time = datetime.fromisoformat(log_entry.timestamp.replace("Z", "+00:00"))
            time_before = (log_time - timedelta(minutes=5)).isoformat() + "Z"
            time_after = (log_time + timedelta(minutes=5)).isoformat() + "Z"

            surrounding_query = {
                "size": 20,  
                "sort": [{"@timestamp": {"order": "asc"}}],
                "query": {
                    "bool": {
                        "must": [
                            {"range": {
                                "@timestamp": {
                                    "gte": time_before,
                                    "lte": time_after
                                }
                            }},
                            *([{"term": {"application": log_entry.application}}] if log_entry.application else []),
                            *([{"term": {"component": log_entry.component}}] if log_entry.component else [])
                        ],
                        "must_not": [
                            {"ids": {"values": [log_entry.id]}}
                        ]
                    }
                }
            }

            surrounding_response = elastic_service.es.search(
                index=actual_index,
                body=surrounding_query
            )

            for hit in surrounding_response['hits']['hits']:
                surrounding_logs.append(LogEntry(
                    id=hit['_id'],
                    timestamp=hit['_source'].get('@timestamp'),
                    level=hit['_source'].get('level'),
                    component=hit['_source'].get('component'),
                    content=hit['_source'].get('content'),
                    application=hit['_source'].get('application'),
                    source_file=hit['_source'].get('source_file'),
                    raw_log=hit['_source'].get('raw_log'),
                    event_id=hit['_source'].get('event_id'),
                    is_anomaly=hit['_source'].get('is_anomaly', False)
                ))

            print(f"Found {len(surrounding_logs)} surrounding logs for log ID {log_entry.id}")

        except Exception as e:
            print(f"Error fetching surrounding logs: {e}")

        analysis = await llm_analyzer.analyze_log_anomaly(log_entry, surrounding_logs)
        
        if not analysis or "error" in analysis:
            raise HTTPException(
                status_code=500,
                detail=f"LLM analysis failed: {analysis.get('error') if analysis else 'Unknown error'}"
            )

        return LLMAnalysisResponse(**analysis)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing anomaly: {str(e)}") 