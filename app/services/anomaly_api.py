from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any, Union
from app.services.elastic import ElasticService
from app.services.llm_analyzer import LLMAnalyzerService
from app.models.log_entry import LogEntry
from pydantic import BaseModel, Field
import asyncio
from app.config.config import config
from datetime import datetime, timedelta, timezone
import json

router = APIRouter()
elastic_service = ElasticService()
llm_analyzer = LLMAnalyzerService()

class AnomalyLogResponse(BaseModel):
    id: str
    timestamp: str  # ISO format
    level: Optional[str] = None
    component: Optional[str] = None
    content: Optional[str] = None
    application: Optional[str] = None
    source_file: Optional[str] = None
    event_id: Optional[str] = None
    is_anomaly: bool
    detection_timestamp: Optional[str] = None

class PaginatedAnomalyResponse(BaseModel):
    total: int
    offset: int
    limit: int
    items: List[AnomalyLogResponse]

class AnomalyOccurrence(BaseModel):
    timestamp: datetime
    event_id: str
    count: int

class AnomalyOccurrenceResponse(BaseModel):
    series: List[AnomalyOccurrence] 

class FieldValuesResponse(BaseModel):
    values: List[str]

class LLMAnalysisRequest(BaseModel):
    log_id: str

class LLMAnalysisResponse(BaseModel):
    anomaly_detection: dict
    root_cause_analysis: dict
    recommendations: dict

class AnomalyGroupResponse(BaseModel):
    event_id: str
    count: int
    first_occurrence: str  # ISO timestamp
    last_occurrence: str   # ISO timestamp
    items: List[AnomalyLogResponse]

class GroupedAnomalyResponse(BaseModel):
    total: int
    offset: int
    limit: int
    groups: List[AnomalyGroupResponse]

@router.get("/anomalies", response_model=Union[PaginatedAnomalyResponse, GroupedAnomalyResponse])
async def get_anomalies(
    limit: int = Query(10, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    start_time: Optional[str] = Query(None, description="Start time in ISO 8601 format (e.g., 2023-05-10T10:00:00Z) or relative (e.g., now-1h)"),
    end_time: Optional[str] = Query(None, description="End time in ISO 8601 format (e.g., 2023-05-10T12:00:00Z) or relative (e.g., now)"),
    levels: Optional[List[str]] = Query(None, description="Comma-separated list of log levels to filter by"),
    applications: Optional[List[str]] = Query(None, description="Comma-separated list of application IDs to filter by"),
    event_ids: Optional[List[str]] = Query(None, description="Comma-separated list of event IDs to filter by"),
    search_query: Optional[str] = Query(None, description="Free text search in log content"),
    group_by: Optional[str] = Query(None, description="Group results by field (e.g., 'event_id')")
):
    """
    Get anomalies with filtering, pagination, and time range.
    Can optionally group results by a field (e.g., event_id).
    """
    try:
        must_conditions = [{"term": {"is_anomaly": True}}]

        time_filter = {}
        if start_time:
            if "now-" in start_time:
                delta_str = start_time.split("-")[1]
                if delta_str.endswith("h"):
                    hours = int(delta_str[:-1])
                    time_filter["gte"] = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
                elif delta_str.endswith("d"):
                    days = int(delta_str[:-1])
                    time_filter["gte"] = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
                else:
                    time_filter["gte"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            else:
                time_filter["gte"] = start_time

        if end_time:
            if end_time == "now":
                time_filter["lte"] = datetime.now(timezone.utc).isoformat()
            else:
                time_filter["lte"] = end_time

        if time_filter:
            must_conditions.append({"range": {"@timestamp": time_filter}})

        if levels:
            must_conditions.append({"terms": {"level.keyword": [level.upper() for level in levels]}})

        if applications:
            must_conditions.append({"terms": {"application.keyword": applications}})

        if event_ids:
            must_conditions.append({"terms": {"event_id.keyword": event_ids}})

        if search_query:
            must_conditions.append({
                "query_string": {
                    "query": search_query,
                    "fields": ["content", "raw_log"],
                    "default_operator": "AND"
                }
            })

        if group_by == "event_id":
            group_query = {
                "size": 0,  
                "query": {"bool": {"must": must_conditions}},
                "aggs": {
                    "by_event_id": {
                        "terms": {
                            "field": "event_id.keyword",
                            "size": limit,
                            "order": {"_count": "desc"}
                        },
                        "aggs": {
                            "first_occurrence": {"min": {"field": "@timestamp"}},
                            "last_occurrence": {"max": {"field": "@timestamp"}},
                            "top_hits": {
                                "top_hits": {
                                    "size": 5, 
                                    "sort": [{"@timestamp": "desc"}]
                                }
                            }
                        }
                    }
                }
            }

            response = elastic_service.es.search(
                index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
                body=group_query
            )

            groups = []
            if "aggregations" in response and "by_event_id" in response["aggregations"]:
                for bucket in response["aggregations"]["by_event_id"]["buckets"]:
                    event_id = bucket["key"]
                    items = []
                    for hit in bucket["top_hits"]["hits"]["hits"]:
                        source = hit["_source"]
                        items.append(AnomalyLogResponse(
                            id=hit["_id"],
                            timestamp=source.get("@timestamp"),
                            level=source.get("level"),
                            component=source.get("component"),
                            content=source.get("content"),
                            application=source.get("application"),
                            source_file=source.get("source_file"),
                            event_id=source.get("event_id"),
                            is_anomaly=source.get("is_anomaly", False),
                            detection_timestamp=source.get("detection_timestamp")
                        ))

                    groups.append(AnomalyGroupResponse(
                        event_id=event_id,
                        count=bucket["doc_count"],
                        first_occurrence=bucket["first_occurrence"]["value_as_string"],
                        last_occurrence=bucket["last_occurrence"]["value_as_string"],
                        items=items
                    ))

            return GroupedAnomalyResponse(
                total=len(groups),
                offset=offset,
                limit=limit,
                groups=groups
            )

        else:
            count_query_body = {"query": {"bool": {"must": must_conditions}}}
            count_response = elastic_service.es.count(
                index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
                body=count_query_body
            )
            total = count_response['count']

            search_query_body = {
                "from": offset,
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": must_conditions}}
            }

            response = elastic_service.es.search(
                index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
                body=search_query_body
            )

            hits = response['hits']['hits']
            anomalies = []
            for hit in hits:
                source = hit['_source']
                anomalies.append(AnomalyLogResponse(
                    id=hit['_id'],
                    timestamp=source.get('@timestamp'),
                    level=source.get('level'),
                    component=source.get('component'),
                    content=source.get('content'),
                    application=source.get('application'),
                    source_file=source.get('source_file'),
                    event_id=source.get('event_id'),
                    is_anomaly=source.get('is_anomaly', False),
                    detection_timestamp=source.get('detection_timestamp')
                ))

            return PaginatedAnomalyResponse(
                total=total,
                offset=offset,
                limit=limit,
                items=anomalies
            )

    except Exception as e:
        print(f"Error in get_anomalies: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching anomalies: {str(e)}")

@router.get("/anomalies/occurrences", response_model=AnomalyOccurrenceResponse)
async def get_anomaly_occurrences(
    start_time: str = Query(..., description="Start time (ISO 8601 or relative, e.g., now-6h)"),
    end_time: str = Query(..., description="End time (ISO 8601 or relative, e.g., now)"),
    interval: str = Query("1h", description="Time interval for aggregation (e.g., 10m, 1h, 1d)"),
    applications: Optional[List[str]] = Query(None),
    levels: Optional[str] = Query(None, description="Comma-separated list of levels (e.g., ERROR,INFO,UNKNOWN)"),
    top_n_event_ids: Optional[int] = Query(5, ge=1, le=20, description="Number of top event_ids to show occurrences for")
):
    try:
        valid_intervals = {
            "1m": "1m", "5m": "5m", "10m": "10m", "15m": "15m", "30m": "30m",
            "1h": "1h", "2h": "2h", "4h": "4h", "6h": "6h", "12h": "12h",
            "1d": "1d", "7d": "7d"
        }
        if interval not in valid_intervals:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid interval. Must be one of: {', '.join(valid_intervals.keys())}"
            )

        parsed_levels = None
        if levels:
            parsed_levels = [level.strip().upper() for level in levels.split(",")]

        print("\n=== Input Parameters ===")
        print(f"start_time: {start_time}")
        print(f"end_time: {end_time}")
        print(f"interval: {interval}")
        print(f"applications: {applications}")
        print(f"levels (original): {levels}")
        print(f"levels (parsed): {parsed_levels}")
        print(f"top_n_event_ids: {top_n_event_ids}")

        must_conditions_base = [{"term": {"is_anomaly": True}}]
        time_filter = {}

        if "now-" in start_time:
            delta_str = start_time.split("-")[1]
            if delta_str.endswith("h"):
                time_filter["gte"] = (datetime.now(timezone.utc) - timedelta(hours=int(delta_str[:-1]))).isoformat()
            elif delta_str.endswith("d"):
                time_filter["gte"] = (datetime.now(timezone.utc) - timedelta(days=int(delta_str[:-1]))).isoformat()
            else:
                time_filter["gte"] = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
        else:
            time_filter["gte"] = start_time

        if end_time == "now":
            time_filter["lte"] = datetime.now(timezone.utc).isoformat()
        else:
            time_filter["lte"] = end_time

        if time_filter:
            must_conditions_base.append({"range": {"@timestamp": time_filter}})

        if applications:
            must_conditions_base.append({"terms": {"application.keyword": applications}})
        
        simple_check_query = {
            "size": 1,
            "query": {"bool": {"must": must_conditions_base}}
        }
        print("\n=== Simple Check Query (without levels) ===")
        print(json.dumps(simple_check_query, indent=2))
        
        simple_check_response = elastic_service.es.search(
            index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
            body=simple_check_query
        )
        simple_check_dict = dict(simple_check_response)
        print("\n=== Simple Check Response (without levels) ===")
        print(f"Total hits: {simple_check_dict['hits']['total']['value']}")
        if simple_check_dict['hits']['hits']:
            print("Sample hit:", json.dumps(simple_check_dict['hits']['hits'][0]['_source'], indent=2))

        if parsed_levels:
            must_conditions_base.append({"terms": {"level.keyword": parsed_levels}})

        print("\n=== Final Query Conditions ===")
        print(json.dumps(must_conditions_base, indent=2))

        top_event_ids_agg_query = {
            "size": 0,
            "query": {"bool": {"must": must_conditions_base}},
            "aggs": {
                "top_event_ids": {
                    "terms": {
                        "field": "event_id.keyword",
                        "size": top_n_event_ids,
                        "order": {"_count": "desc"}
                    }
                }
            }
        }

        print("\n=== Top Event IDs Query ===")
        print(json.dumps(top_event_ids_agg_query, indent=2))
        
        agg_response = elastic_service.es.search(
            index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
            body=top_event_ids_agg_query
        )
        agg_response_dict = dict(agg_response)
        print("\n=== Top Event IDs Response ===")
        print(json.dumps(agg_response_dict, indent=2))

        top_events = []
        if "aggregations" in agg_response_dict and "top_event_ids" in agg_response_dict["aggregations"]:
            for bucket in agg_response_dict["aggregations"]["top_event_ids"]["buckets"]:
                top_events.append(bucket["key"])

        if not top_events:
            print("\nNo top events found in aggregations")
            return AnomalyOccurrenceResponse(series=[])

        print("\n=== Top Events Found ===")
        print(top_events)

        must_conditions_timeseries = list(must_conditions_base)
        must_conditions_timeseries.append({"terms": {"event_id.keyword": top_events}})

        timeseries_query = {
            "size": 0,
            "query": {"bool": {"must": must_conditions_timeseries}},
            "aggs": {
                "events_over_time": {
                    "terms": {
                        "field": "event_id.keyword",
                        "size": top_n_event_ids
                    },
                    "aggs": {
                        "occurrences": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": interval,
                                "min_doc_count": 1
                            }
                        }
                    }
                }
            }
        }

        print("\n=== Timeseries Query ===")
        print(json.dumps(timeseries_query, indent=2))
        
        ts_response = elastic_service.es.search(
            index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
            body=timeseries_query
        )
        ts_response_dict = dict(ts_response)
        print("\n=== Timeseries Response ===")
        print(json.dumps(ts_response_dict, indent=2))

        occurrences = []
        if "aggregations" in ts_response_dict and "events_over_time" in ts_response_dict["aggregations"]:
            for event_bucket in ts_response_dict["aggregations"]["events_over_time"]["buckets"]:
                event_id = event_bucket["key"]
                for time_bucket in event_bucket["occurrences"]["buckets"]:
                    ts_dt = datetime.fromtimestamp(time_bucket["key"] / 1000.0, tz=timezone.utc)
                    occurrences.append(AnomalyOccurrence(
                        timestamp=ts_dt,
                        event_id=event_id,
                        count=time_bucket["doc_count"]
                    ))

        occurrences.sort(key=lambda x: (x.timestamp, x.event_id))
        return AnomalyOccurrenceResponse(series=occurrences)

    except Exception as e:
        print(f"\nError in get_anomaly_occurrences: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching anomaly occurrences: {str(e)}")

async def get_distinct_field_values(
    field_name: str,
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    applications: Optional[List[str]] = Query(None)
) -> FieldValuesResponse:
    """Helper function to get distinct values for a field."""
    try:
        must_conditions = []
        time_filter = {}

        if start_time:
            if "now-" in start_time:
                delta_str = start_time.split("-")[1]
                if delta_str.endswith("h"):
                    time_filter["gte"] = (datetime.now(timezone.utc) - timedelta(hours=int(delta_str[:-1]))).isoformat()
                else:
                    time_filter["gte"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
            else:
                time_filter["gte"] = start_time

        if end_time:
            if end_time == "now":
                time_filter["lte"] = datetime.now(timezone.utc).isoformat()
            else:
                time_filter["lte"] = end_time

        if time_filter:
            must_conditions.append({"range": {"@timestamp": time_filter}})
        if applications:
            must_conditions.append({"terms": {"application.keyword": applications}})

        query_body = {
            "size": 0,
            "query": {"bool": {"must": must_conditions}} if must_conditions else {"match_all": {}},
            "aggs": {
                "distinct_values": {
                    "terms": {
                        "field": f"{field_name}.keyword",
                        "size": 1000,
                        "order": {"_key": "asc"}
                    }
                }
            }
        }

        response = elastic_service.es.search(
            index=f"{config.ELASTICSEARCH_LOG_INDEX}-*",
            body=query_body
        )

        values = []
        if "aggregations" in response and "distinct_values" in response["aggregations"]:
            for bucket in response["aggregations"]["distinct_values"]["buckets"]:
                values.append(bucket["key"])

        return FieldValuesResponse(values=values)

    except Exception as e:
        print(f"Error fetching distinct values for {field_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching distinct values for {field_name}: {str(e)}")

@router.get("/anomalies/event_ids", response_model=FieldValuesResponse)
async def get_distinct_event_ids(
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    applications: Optional[List[str]] = Query(None)
):
    """Get distinct anomaly event_ids within a time range, filtered by applications."""
    return await get_distinct_field_values("event_id", start_time, end_time, applications)

@router.get("/anomalies/levels", response_model=FieldValuesResponse)
async def get_distinct_levels(
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    applications: Optional[List[str]] = Query(None)
):
    """Get distinct log levels associated with anomalies within a time range, filtered by applications."""
    return await get_distinct_field_values("level", start_time, end_time, applications)

@router.get("/anomalies/components", response_model=FieldValuesResponse)
async def get_distinct_components(
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    applications: Optional[List[str]] = Query(None)
):
    """Get distinct components associated with anomalies within a time range, filtered by applications."""
    return await get_distinct_field_values("component", start_time, end_time, applications)

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