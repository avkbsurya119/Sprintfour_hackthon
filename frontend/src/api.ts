import type {
  Document,
  ReviewItems,
  Summary,
  SpanType,
  SanitizeRequest,
  SanitizeResponse,
  SanitizedOutput,
  PseudonymMapping,
} from './types';

const API_BASE = 'http://localhost:8000/api';

export async function fetchDocument(id: number): Promise<Document> {
  const response = await fetch(`${API_BASE}/documents/${id}`);
  if (!response.ok) throw new Error('Failed to fetch document');
  return response.json();
}

export async function fetchReviewItems(documentId: number): Promise<ReviewItems> {
  const response = await fetch(`${API_BASE}/documents/${documentId}/review-items`);
  if (!response.ok) throw new Error('Failed to fetch review items');
  return response.json();
}

export interface DecisionResult {
  id: number;
  span_type: string;
  span_id: number;
  decision: string;
}

export async function submitDecision(
  documentId: number,
  spanType: SpanType,
  spanId: number,
  decision: string
): Promise<DecisionResult> {
  const response = await fetch(`${API_BASE}/documents/${documentId}/decisions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      span_type: spanType,
      span_id: spanId,
      decision,
    }),
  });
  if (!response.ok) throw new Error('Failed to submit decision');
  return response.json();
}

export async function deleteDecision(
  documentId: number,
  decisionId: number
): Promise<void> {
  const response = await fetch(
    `${API_BASE}/documents/${documentId}/decisions/${decisionId}`,
    { method: 'DELETE' }
  );
  if (!response.ok) throw new Error('Failed to delete decision');
}

export async function completeReview(documentId: number): Promise<Summary> {
  const response = await fetch(`${API_BASE}/documents/${documentId}/complete`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to complete review');
  }
  return response.json();
}

export async function fetchSummary(documentId: number): Promise<Summary> {
  const response = await fetch(`${API_BASE}/documents/${documentId}/summary`);
  if (!response.ok) throw new Error('Failed to fetch summary');
  return response.json();
}

export interface Span {
  id: number;
  start_offset: number;
  end_offset: number;
  text_content: string;
  pii_category?: string;
  pattern_source?: string;
  decision?: 'approve' | 'reject' | 'redact' | 'dismiss';
  ensemble_sources?: string[];
  ensemble_agreement_count?: number;
  ensemble_conflict_types?: string[];
}

export interface DocumentListItem {
  id: number;
  title: string;
  status: string;
  created_at: string;
  is_demo: boolean;
}

export async function listDocuments(): Promise<DocumentListItem[]> {
  const response = await fetch(`${API_BASE}/documents`);
  if (!response.ok) throw new Error('Failed to list documents');
  return response.json();
}

export interface UploadResult {
  document_id: number;
  title: string;
  detector_span_count: number;
  risk_flag_count: number;
  file_type: string;
  char_count: number;
}

export async function uploadDocument(file: File): Promise<UploadResult> {
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch(`${API_BASE}/documents/upload`, {
    method: 'POST',
    body: formData,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Upload failed' }));
    throw new Error(error.detail || 'Upload failed');
  }
  return response.json();
}

// ============================================================================
// Sanitization API
// ============================================================================

export async function sanitizeDocument(
  documentId: number,
  request: SanitizeRequest
): Promise<SanitizeResponse> {
  const response = await fetch(`${API_BASE}/documents/${documentId}/sanitize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Sanitization failed' }));
    throw new Error(error.detail || 'Sanitization failed');
  }
  return response.json();
}

export async function getSanitizedOutputs(documentId: number): Promise<SanitizedOutput[]> {
  const response = await fetch(`${API_BASE}/documents/${documentId}/sanitized-outputs`);
  if (!response.ok) throw new Error('Failed to fetch sanitized outputs');
  return response.json();
}

export async function getSanitizedOutput(
  documentId: number,
  outputId: number
): Promise<SanitizedOutput> {
  const response = await fetch(`${API_BASE}/documents/${documentId}/sanitized-outputs/${outputId}`);
  if (!response.ok) throw new Error('Failed to fetch sanitized output');
  return response.json();
}

export async function getPseudonymMappings(documentId: number): Promise<PseudonymMapping[]> {
  const response = await fetch(`${API_BASE}/documents/${documentId}/pseudonym-mappings`);
  if (!response.ok) throw new Error('Failed to fetch pseudonym mappings');
  return response.json();
}

// ============================================================================
// Manual Span Management API
// ============================================================================

export interface ManualSpanCreate {
  start_offset: number;
  end_offset: number;
  pii_category: string;
  span_type?: 'detector' | 'risk_flag';
}

export interface ManualSpanResponse {
  id: number;
  span_type: string;
  start_offset: number;
  end_offset: number;
  text_content: string;
  pii_category: string;
  is_manual: boolean;
}

export async function createManualSpan(
  documentId: number,
  request: ManualSpanCreate
): Promise<ManualSpanResponse> {
  const response = await fetch(`${API_BASE}/documents/${documentId}/spans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to create span' }));
    throw new Error(error.detail || 'Failed to create span');
  }
  return response.json();
}

export async function updateSpanCategory(
  documentId: number,
  spanType: 'detector' | 'risk_flag',
  spanId: number,
  piiCategory: string
): Promise<{ success: boolean }> {
  const response = await fetch(
    `${API_BASE}/documents/${documentId}/spans/${spanType}/${spanId}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pii_category: piiCategory }),
    }
  );
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to update span' }));
    throw new Error(error.detail || 'Failed to update span');
  }
  return response.json();
}

export async function deleteSpan(
  documentId: number,
  spanType: 'detector' | 'risk_flag',
  spanId: number
): Promise<{ success: boolean }> {
  const response = await fetch(
    `${API_BASE}/documents/${documentId}/spans/${spanType}/${spanId}`,
    { method: 'DELETE' }
  );
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to delete span' }));
    throw new Error(error.detail || 'Failed to delete span');
  }
  return response.json();
}
