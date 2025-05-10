from app.config.config import config
import httpx 
import json
from typing import List, Dict, Any, Optional
import asyncio
from datetime import datetime, timedelta

class GeminiPart:
    def __init__(self, text: str):
        self.text = text

class GeminiContent:
    def __init__(self, parts: List[GeminiPart], role: Optional[str] = None):
        self.parts = parts
        if role:
            self.role = role

class GeminiRequestBody:
    def __init__(self, contents: List[GeminiContent]):
        self.contents = contents

class GeminiCandidate:
    def __init__(self, content: GeminiContent, finish_reason: str, index: int):
        self.content = content
        self.finishReason = finish_reason
        self.index = index

class GeminiResponse:
    def __init__(self, candidates: List[GeminiCandidate]):
        self.candidates = candidates


class LLMAnalyzerService:
    def __init__(self):
        self.api_key = config.GEMINI_API_KEY
        self.model_id = "gemini-1.5-flash-latest" 
        if not self.api_key:
            print("ERROR: LLMAnalyzerService initialized without GEMINI_API_KEY.")

    def _build_prompt(self, time_range_str: str, log_entries_str: str, spark_context_str: Optional[str] = None) -> str:
        prompt = f"""
You are an expert AI system for analyzing Apache Spark logs and identifying anomalies, root causes, and suggesting solutions. Your task is to analyze the provided Spark logs and generate a detailed analysis in JSON format.

INPUT:
- Time Range: {time_range_str}
- Spark Log Entries:
{log_entries_str}
- Spark Context: {spark_context_str if spark_context_str else "Not provided."}

INSTRUCTIONS:
1. Analyze the Spark logs to identify any anomalies or issues.
2. Pay special attention to:
   - Task execution patterns
   - Memory usage and cache behavior
   - Resource allocation
   - Executor lifecycle
   - Performance bottlenecks
3. Determine the root cause of any identified issues.
4. Suggest specific Spark configuration changes, code optimizations, or other solutions.
5. Format your response as a *single, valid JSON object only*, matching the structure specified below. Do not include any introductory text like "Here is the JSON..." or markdown formatting like ```json ... ```.

SPARK-SPECIFIC GUIDANCE:
- Look for patterns in cache misses that might indicate memory pressure or improper caching.
- Analyze task execution times for performance bottlenecks.
- Check for executor failures or resource constraints.
- Identify potential code issues like inefficient operations or poor partitioning.
- Consider Spark configuration parameters that might need adjustment.

OUTPUT FORMAT:
{{
  "anomaly_detection": {{
    "anomaly_id": "SPK-[DATE]-[SEQUENCE]",
    "timestamp": "When the anomaly was detected",
    "severity": "HIGH/MEDIUM/LOW",
    "type": "CACHE_MISS_BURST/TASK_FAILURE/EXECUTOR_FAILURE/MEMORY_PRESSURE/etc.",
    "description": "A detailed description of the anomaly",
    "affected_component": "The Spark component affected (e.g., executor, storage, cache) ",
    "normal_threshold": "What would be considered normal behavior",
    "observed_value": "The actual observed behavior",
    "deviation_factor": "How much the observed value deviates from normal",
    "related_events": [
      {{
        "timestamp": "Timestamp of related event",
        "event": "Description of the event",
        "count": "Number of occurrences if applicable"
      }}
    ],
    "confidence": "A value between 0 and 1 indicating confidence in the detection"
  }},
  "root_cause_analysis": {{
    "analysis_id": "RCA-SPK-[DATE]-[SEQUENCE]",
    "anomaly_id": "The ID of the related anomaly",
    "root_causes": [
      {{
        "cause": "INSUFFICIENT_CACHING/MEMORY_PRESSURE/CODE_INEFFICIENCY/etc.",
        "description": "A detailed description of the cause",
        "evidence": [
          "Evidence point 1",
          "Evidence point 2"
        ],
        "confidence": "A value between 0 and 1 indicating confidence in this cause"
      }}
    ],
    "performance_impact": {{
      "estimated_slowdown": "Estimated performance impact",
      "reason": "Reason for the performance impact",
      "affected_operations": ["List of affected operations"]
    }}
  }},
  "recommendations": {{
    "recommendation_id": "REC-SPK-[DATE]-[SEQUENCE]",
    "anomaly_id": "The ID of the related anomaly",
    "recommendations": [
      {{
        "action": "CODE_OPTIMIZATION/MEMORY_CONFIGURATION/PERSISTENCE_LEVEL_CHANGE/etc.",
        "description": "A detailed description of the action",
        "specific_steps": [
          "Add .cache() or .persist() call for RDD_2 before actions",
          "Increase spark.memory.fraction to 0.8",
          "Change persistence level to MEMORY_AND_DISK"
        ],
        "expected_outcome": "What should happen after taking this action",
        "priority": "HIGH/MEDIUM/LOW",
        "effort_level": "HIGH/MEDIUM/LOW",
        "success_rate": "A value between 0 and 1 indicating the likelihood of success"
      }}
    ],
    "optimization_opportunities": [
      {{
        "opportunity": "PARTITION_TUNING/BROADCAST_VARIABLES/etc.",
        "description": "A detailed description of the opportunity",
        "implementation": "How to implement this optimization"
      }}
    ]
  }}
}}

REQUIREMENTS:
- Be specific and detailed in your analysis of Spark logs
- Provide Spark-specific configuration and code recommendations
- Include code examples where appropriate
- Ensure your JSON is properly formatted and adheres strictly to the OUTPUT FORMAT.
- Assign realistic confidence scores based on the evidence available.
"""
        return prompt

    async def analyze_log_anomaly(self, log_entry: Any, surrounding_logs: List[Any] = None) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            print("LLM analysis skipped: API key not configured.")
            return None

        print(f"LLMAnalyzer: Analyzing log ID {log_entry.id if hasattr(log_entry, 'id') else 'N/A'}")

        # Get 1 main log and 5 logs before and after as context
        log_entries_for_prompt = []
        main_log_dict = log_entry.to_dict() 
        log_entries_for_prompt.append(main_log_dict)

        if surrounding_logs:
            for sl in surrounding_logs:
                log_entries_for_prompt.append(sl.to_dict())

        log_entries_for_prompt.sort(key=lambda x: x.get('@timestamp', ''))


        log_entries_str_list = []
        for l_dict in log_entries_for_prompt:
            log_str = f"Timestamp: {l_dict.get('@timestamp')}, Level: {l_dict.get('level')}, Component: {l_dict.get('component')}, Message: {l_dict.get('content')}"
            log_entries_str_list.append(log_str)
        log_entries_str_for_llm = "\n".join(log_entries_str_list)


        try:
            log_time = datetime.fromisoformat(log_entry.timestamp.replace("Z", "+00:00"))
            start_time = (log_time - timedelta(minutes=5)).isoformat() + "Z"
            end_time = (log_time + timedelta(minutes=5)).isoformat() + "Z"
            time_range_str = f"{start_time} to {end_time}"
        except Exception as e:
            print(f"Error parsing log timestamp for LLM context: {e}")
            time_range_str = "Could not determine specific time range for this log."


        prompt = self._build_prompt(time_range_str=time_range_str, log_entries_str=log_entries_str_for_llm)
        print(f"LLMAnalyzer: Sending prompt to Gemini for log ID {log_entry.id if hasattr(log_entry, 'id') else 'N/A'}")


        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_id}:generateContent?key={self.api_key}"
        request_body_data = {
            "contents": [{"parts": [{"text": prompt}]}],
        }
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                response = await client.post(url, json=request_body_data, headers={"Content-Type": "application/json"})
                response.raise_for_status()
                
                response_data = response.json()
                print(f"Gemini raw response: {json.dumps(response_data, indent=2)}")

                if response_data.get("candidates") and len(response_data["candidates"]) > 0:
                    candidate = response_data["candidates"][0]
                    if candidate.get("content") and candidate["content"].get("parts") and len(candidate["content"]["parts"]) > 0:
                        generated_text = candidate["content"]["parts"][0].get("text", "")
                        
                        try:
                            if "```json" in generated_text:
                                json_text = generated_text.split("```json")[1].split("```")[0].strip()
                            else:
                                json_text = generated_text.strip()
                            
                            llm_analysis_dict = json.loads(json_text)
                            print(f"LLMAnalyzer: Successfully parsed analysis for log ID {log_entry.id if hasattr(log_entry, 'id') else 'N/A'}")
                            return llm_analysis_dict
                        except json.JSONDecodeError as je:
                            print(f"LLMAnalyzer: Failed to parse JSON from Gemini response for log ID {log_entry.id if hasattr(log_entry, 'id') else 'N/A'}. Error: {je}")
                            print(f"LLM Raw Text Output: {generated_text}")
                            return {"error": "LLM_RESPONSE_NOT_JSON", "raw_output": generated_text} 
                    else:
                        print(f"LLMAnalyzer: No content parts in Gemini candidate for log ID {log_entry.id if hasattr(log_entry, 'id') else 'N/A'}")
                else:
                    print(f"LLMAnalyzer: No candidates in Gemini response for log ID {log_entry.id if hasattr(log_entry, 'id') else 'N/A'}")
                
                return {"error": "LLM_UNEXPECTED_RESPONSE_STRUCTURE", "details": response_data}

            except httpx.HTTPStatusError as e:
                print(f"LLMAnalyzer: HTTP error calling Gemini API for log ID {log_entry.id if hasattr(log_entry, 'id') else 'N/A'}: {e.response.status_code} - {e.response.text}")
                return {"error": f"GEMINI_API_HTTP_ERROR_{e.response.status_code}", "details": e.response.text}
            except Exception as e:
                print(f"LLMAnalyzer: General error calling Gemini API for log ID {log_entry.id if hasattr(log_entry, 'id') else 'N/A'}: {str(e)}")
                return {"error": "GEMINI_API_REQUEST_FAILED", "details": str(e)}

