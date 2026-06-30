import re
from typing import List, Dict, Any
from app.risk_scorer import PHONE_PATTERN, POSTAL_PATTERN, SSN_PATTERN, EMAIL_PATTERN, NAME_PATTERN

import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

# 1. Initialize Presidio with the small model
configuration = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}
provider = NlpEngineProvider(nlp_configuration=configuration)
nlp_engine = provider.create_engine()
analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

# 2. Initialize spaCy
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    nlp = None

def run_regex(text: str) -> List[Dict[str, Any]]:
    """Runs the existing regex detector patterns."""
    detections = []
    
    for match in SSN_PATTERN.finditer(text):
        detections.append({'start': match.start(), 'end': match.end(), 'text': match.group(), 'type': 'ssn', 'source': 'regex'})
    for match in EMAIL_PATTERN.finditer(text):
        detections.append({'start': match.start(), 'end': match.end(), 'text': match.group(), 'type': 'email', 'source': 'regex'})
    for match in PHONE_PATTERN.finditer(text):
        detections.append({'start': match.start(), 'end': match.end(), 'text': match.group(), 'type': 'phone', 'source': 'regex'})
    for match in POSTAL_PATTERN.finditer(text):
        detections.append({'start': match.start(), 'end': match.end(), 'text': match.group(), 'type': 'postal_code', 'source': 'regex'})
    for match in NAME_PATTERN.finditer(text):
        detections.append({'start': match.start(), 'end': match.end(), 'text': match.group(), 'type': 'name', 'source': 'regex'})
        
    return detections

def run_presidio(text: str) -> List[Dict[str, Any]]:
    """Runs Presidio Analyzer."""
    detections = []
    results = analyzer.analyze(text=text, entities=[], language='en')
    for res in results:
        t = res.entity_type.lower()
        # map presidio types to our types roughly
        if t == 'person': t = 'name'
        elif t == 'email_address': t = 'email'
        elif t == 'phone_number': t = 'phone'
        elif t == 'us_ssn': t = 'ssn'
        
        detections.append({
            'start': res.start,
            'end': res.end,
            'text': text[res.start:res.end],
            'type': t,
            'source': 'presidio'
        })
    return detections

def run_spacy(text: str) -> List[Dict[str, Any]]:
    """Runs spaCy NER."""
    detections = []
    if not nlp: return detections
    
    doc = nlp(text)
    for ent in doc.ents:
        t = ent.label_.lower()
        if t == 'person': t = 'name'
        elif t in ['gpe', 'loc']: t = 'location'
        elif t == 'org': t = 'organization'
        elif t == 'date': t = 'date'
        else:
            continue # ignore non-pii entities
            
        detections.append({
            'start': ent.start_char,
            'end': ent.end_char,
            'text': ent.text,
            'type': t,
            'source': 'spacy'
        })
    return detections

def run_rules(text: str) -> List[Dict[str, Any]]:
    """Independent Rule-Based Detector."""
    detections = []
    
    # 1. URL pattern
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    for m in url_pattern.finditer(text):
        detections.append({'start': m.start(), 'end': m.end(), 'text': m.group(), 'type': 'url', 'source': 'rules'})
        
    # 2. @mentions / Usernames
    username_pattern = re.compile(r'(?<=^|(?<=[^a-zA-Z0-9-_\.]))@([A-Za-z]+[A-Za-z0-9-_]+)')
    for m in username_pattern.finditer(text):
        detections.append({'start': m.start(), 'end': m.end(), 'text': m.group(), 'type': 'username', 'source': 'rules'})
        
    # 3. Simple ID / Account numbers (10+ digits or mixed alphanumeric)
    id_pattern = re.compile(r'\b[A-Z0-9]{10,20}\b')
    for m in id_pattern.finditer(text):
        if any(c.isdigit() for c in m.group()) and any(c.isalpha() for c in m.group()):
            detections.append({'start': m.start(), 'end': m.end(), 'text': m.group(), 'type': 'id_number', 'source': 'rules'})
            
    return detections

def reconcile_spans(all_detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Takes a flat list of all detections from all sources and merges overlapping ones.
    """
    if not all_detections:
        return []
        
    # Sort by start offset
    all_detections.sort(key=lambda x: x['start'])
    
    clusters = []
    current_cluster = [all_detections[0]]
    current_end = all_detections[0]['end']
    
    for det in all_detections[1:]:
        if det['start'] < current_end:
            # Overlap
            current_cluster.append(det)
            current_end = max(current_end, det['end'])
        else:
            clusters.append(current_cluster)
            current_cluster = [det]
            current_end = det['end']
    clusters.append(current_cluster)
    
    reconciled = []
    for cluster in clusters:
        start = min(d['start'] for d in cluster)
        end = max(d['end'] for d in cluster)
        
        sources = list(set(d['source'] for d in cluster))
        types = list(set(d['type'] for d in cluster))
        
        # We assume the text from the first detection or a substring of original text 
        # Since we just have the detections, we'll pick the longest text
        longest_text = max((d['text'] for d in cluster), key=len)
        
        reconciled.append({
            'start': start,
            'end': end,
            'text': longest_text,
            'types': types,
            'sources': sources,
            'agreement_count': len(sources)
        })
        
    return reconciled

def run_ensemble(text: str) -> List[Dict[str, Any]]:
    d1 = run_regex(text)
    d2 = run_presidio(text)
    d3 = run_spacy(text)
    d4 = run_rules(text)
    
    all_det = d1 + d2 + d3 + d4
    return reconcile_spans(all_det)

def apply_ensemble_metadata(target_spans, reconciled_spans):
    for span in target_spans:
        overlapping = [rs for rs in reconciled_spans if max(span.start_offset, rs['start']) < min(span.end_offset, rs['end'])]
        if overlapping:
            rs = overlapping[0]
            span.ensemble_sources = rs['sources']
            span.ensemble_agreement_count = rs['agreement_count']
            span.ensemble_conflict_types = rs['types'] if len(rs['types']) > 1 else None
        else:
            span.ensemble_sources = ['regex']
            span.ensemble_agreement_count = 1
            span.ensemble_conflict_types = None
