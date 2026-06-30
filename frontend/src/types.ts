export interface Document {
  id: number;
  title: string;
  content: string;
  status: 'pending_review' | 'in_progress' | 'completed';
  created_at: string;
}

export type PIICategory =
  | 'name'
  | 'email'
  | 'phone'
  | 'ssn'
  | 'credit_card'
  | 'location'
  | 'organization'
  | 'date'
  | 'postal_code'
  | 'url'
  | 'username'
  | 'id_number'
  | 'ip_address'
  | 'money'
  | 'percentage'
  | 'other';

export interface DetectorSpan {
  id: number;
  start_offset: number;
  end_offset: number;
  text_content: string;
  pii_category?: PIICategory | string;
  confidence_score?: number;
  is_manual?: boolean;
  decision: 'approve' | 'reject' | null;
  ensemble_sources?: string[];
  ensemble_agreement_count?: number;
  ensemble_conflict_types?: string[];
}

export interface RiskFlag {
  id: number;
  start_offset: number;
  end_offset: number;
  text_content: string;
  pii_category: PIICategory | string;
  pattern_source: string;
  confidence_score?: number;
  is_manual?: boolean;
  decision: 'redact' | 'dismiss' | null;
  ensemble_sources?: string[];
  ensemble_agreement_count?: number;
  ensemble_conflict_types?: string[];
}

export interface ReviewItems {
  detector_spans: DetectorSpan[];
  risk_flags: RiskFlag[];
}

export interface Summary {
  exposures_caught: number;
  exposures_missed: number;
  unnecessary_redactions_fixed: number;
  correct_redactions_kept: number;
  total_reviewed: number;
  document_status: string;
}

export type SpanType = 'detector' | 'risk_flag';

export interface ReviewableItem {
  type: SpanType;
  id: number;
  start_offset: number;
  end_offset: number;
  text_content: string;
  decision: string | null;
  pii_category?: PIICategory | string;
  confidence_score?: number;
  is_manual?: boolean;
  urgency: 'critical' | 'elevated' | 'standard';
  ensemble_sources?: string[];
  ensemble_agreement_count?: number;
  ensemble_conflict_types?: string[];
}

// ============================================================================
// Sanitization Types
// ============================================================================

export type SanitizationMode = 'redact' | 'pseudonymize';
export type RedactionStyle = 'bars' | 'brackets';

export interface SanitizeRequest {
  mode: SanitizationMode;
  redaction_style?: RedactionStyle;
}

export interface RedactionInfo {
  original: string;
  category: string;
  start: number;
  end: number;
  replacement: string;
}

export interface SanitizeResponse {
  document_id: number;
  mode: SanitizationMode;
  content: string;
  redaction_count: number;
  redactions?: RedactionInfo[];
  pseudonym_mapping?: Record<string, string>;
  output_id: number;
}

export interface SanitizedOutput {
  id: number;
  document_id: number;
  mode: SanitizationMode;
  redaction_style?: RedactionStyle;
  content: string;
  mapping?: Record<string, string>;
  created_at: string;
}

export interface PseudonymMapping {
  original: string;
  pseudonym: string;
  category: string;
}
