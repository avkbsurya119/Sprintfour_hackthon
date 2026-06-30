export interface Document {
  id: number;
  title: string;
  content: string;
  status: 'pending_review' | 'in_progress' | 'completed';
  created_at: string;
}

export interface DetectorSpan {
  id: number;
  start_offset: number;
  end_offset: number;
  text_content: string;
  decision: 'approve' | 'reject' | null;
}

export interface RiskFlag {
  id: number;
  start_offset: number;
  end_offset: number;
  text_content: string;
  pii_category: 'phone' | 'ssn' | 'email' | 'name';
  pattern_source: string;
  decision: 'redact' | 'dismiss' | null;
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
  pii_category?: string;
  urgency: 'critical' | 'elevated' | 'standard';
}
