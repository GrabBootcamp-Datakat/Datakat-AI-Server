from app.models.event import Event
from app.models.log_entry import LogEntry
from app.services.preprocess import PreprocessService
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict
from sklearn.cluster import DBSCAN
from fuzzywuzzy import fuzz
from typing import List
from functools import lru_cache
import numpy as np


class ClusteringService:
    def __init__(self):
        self.preprocess_service = PreprocessService()
        # Pre-initialize vectorizers to avoid repeated initialization
        self.tfidf_vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_df=0.9, min_df=1, stop_words='english')
        self.template_vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        # Cache for preprocessing results
        self._template_cache = {}
        self._normalized_log_cache = {}

    @lru_cache(maxsize=1024)
    def _normalize_log(self, content: str) -> str:
        """Cached version of normalize_log"""
        return self.preprocess_service.normalize_log(content)
    
    @lru_cache(maxsize=1024)
    def _normalize_log_template(self, content: str) -> str:
        """Cached version of normalize_log_template"""
        return self.preprocess_service.normalize_log_template(content)

    @lru_cache(maxsize=1024)
    def _normalize_template(self, template: str) -> str:
        """Cached version of normalize_template"""
        return self.preprocess_service.normalize_template(template)

    def _generate_template_from_cluster(self, logs: List[str]) -> str:
        """Generate a template from a cluster of logs using a faster algorithm"""
        if not logs:
            return ""
        
        if len(logs) == 1:
            return logs[0]  # No need to process for a single log
            
        # Convert logs to 2D array for faster processing
        token_arrays = [log.split() for log in logs]
        max_length = max(len(tokens) for tokens in token_arrays)
        
        # Create a template array
        template_tokens = []
        
        # Find common tokens
        for i in range(max_length):
            tokens_at_position = [tokens[i] if i < len(tokens) else None for tokens in token_arrays]
            unique_tokens = set(t for t in tokens_at_position if t is not None)
            
            if len(unique_tokens) == 1:
                template_tokens.append(next(iter(unique_tokens)))
            else:
                template_tokens.append("<*>")

        # Now, let's check and merge consecutive <*> tokens into one
        merged_template_tokens = []
        previous_token = None

        for token in template_tokens:
            if token == "<*>":
                if previous_token == "<*>":
                    continue
            merged_template_tokens.append(token)
            previous_token = token
        
        return ' '.join(merged_template_tokens)
    
    def _is_template_too_generic(self, template: str, threshold: float = 0.8) -> bool:
        """Check if a template is too generic (contains too many wildcards)"""
        tokens = template.strip().split()
        if not tokens:
            return True
        
        wildcard_count = sum(1 for token in tokens if token == "<*>")
        return (wildcard_count / len(tokens)) >= threshold
    
    def _merge_similar_templates(self, templates: List[Event], threshold=0.9) -> List[Event]:
        """Merge similar templates using TF-IDF and cosine similarity"""
        if not templates:
            return []
            
        # Normalize templates once and store for reuse
        normalized_templates = [self._normalize_template(t.template) for t in templates]
        
        # Vectorize templates
        X = self.template_vectorizer.fit_transform(normalized_templates)
        
        # Calculate similarity matrix
        sim_matrix = cosine_similarity(X)
        
        # Use numpy for faster operations
        n = len(templates)
        merged = np.zeros(n, dtype=bool)
        merged_templates = []

        for i in range(n):
            if merged[i]:
                continue

            # Find similar templates
            similar_indices = np.where(sim_matrix[i] >= threshold)[0]
            similar_indices = similar_indices[similar_indices > i]  # Only consider j > i
            
            # Group similar templates
            group = [templates[i]]
            for j in similar_indices:
                if not merged[j]:
                    group.append(templates[j])
                    merged[j] = True

            # Choose representative template (median length)
            sorted_group = sorted(group, key=lambda t: len(t.template))
            chosen = sorted_group[len(group)//2]
            merged_templates.append(chosen)

        return merged_templates
    
    def cluster_and_generate_templates(self, unknown_logs: List[LogEntry], event_templates: List[Event]):
        """Cluster logs and generate templates with optimized performance"""
        if not unknown_logs:
            return event_templates

        # Preprocess logs in batch_normalize_log
        contents = [self._normalize_log(log.content) for log in unknown_logs]
        
        # Check if we have valid contents after normalization
        valid_contents = [c for c in contents if c and len(c.strip()) > 0]
        if not valid_contents:
            print("No valid log contents for clustering")
            return event_templates
            
        # Vectorize logs
        try:
            X = self.tfidf_vectorizer.fit_transform(valid_contents)
        except Exception as e:
            print(f"Error vectorizing logs: {str(e)}")
            return event_templates
        
        # Optimize DBSCAN parameters for speed (larger eps = fewer clusters)
        clustering = DBSCAN(eps=0.5, min_samples=2, metric="cosine", n_jobs=-1).fit(X)
        
        # Group logs into clusters using numpy for speed
        labels = clustering.labels_
        
        # Create a mapping from labels to log indices
        cluster_indices = defaultdict(list)
        for i, label in enumerate(labels):
            if label != -1:  # Skip outliers
                cluster_indices[label].append(i)
        
        # Generate templates
        raw_templates = []
        log_to_raw_template = {}
        generic_logs = []
        
        # Process clusters
        for label, indices in cluster_indices.items():
            cluster_logs = [unknown_logs[i].content for i in indices]
            template = self._generate_template_from_cluster(cluster_logs)
            
            if self._is_template_too_generic(template):
                for i in indices:
                    generic_logs.append(unknown_logs[i])
                continue
            
            raw_templates.append(template)
            for i in indices:
                log_to_raw_template[unknown_logs[i]] = template
        
        # Merge similar templates
        raw_template_objs = event_templates + [Event("", t, is_abnormal=True) for t in raw_templates]
        unique_templates = set()
        unique_events = []

        for event in raw_template_objs:
            if event.template not in unique_templates:
                unique_templates.add(event.template)
                unique_events.append(event)

        raw_template_objs = unique_events
        merged_templates = self._merge_similar_templates(raw_template_objs, threshold=0.7)
        
        # Prepare final templates and mapping
        final_templates = []
        normalized_to_event = {}
        
        for idx, merged in enumerate(merged_templates):
            event_id = f"E{idx + 1}"
            merged.event_id = event_id
            final_templates.append(merged)
            norm_tpl = self._normalize_template(merged.template)
            normalized_to_event[norm_tpl] = event_id
        
        # Process logs more efficiently
        for log, raw_template in log_to_raw_template.items():
            norm = self._normalize_template(raw_template)
            
            # Direct match (fast path)
            if norm in normalized_to_event:
                log.event_id = normalized_to_event[norm]
                log.is_anomaly = True
                continue
            
            # Find best match using fuzzy matching
            best_score = 0
            best_event_id = None
            
            for norm2, event_id in normalized_to_event.items():
                score = fuzz.partial_ratio(norm, norm2)
                if score > best_score:
                    best_score = score
                    best_event_id = event_id
            
            if best_event_id and best_score >= 70:
                log.event_id = best_event_id
                log.is_anomaly = True
        
        # Process generic logs
        for log in generic_logs:
            log.event_id = "E0"
            log.is_anomaly = True
        
        return final_templates