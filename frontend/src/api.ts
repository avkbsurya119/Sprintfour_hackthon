import type { Document, ReviewItems, Summary, SpanType } from './types';

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

export async function submitDecision(
  documentId: number,
  spanType: SpanType,
  spanId: number,
  decision: string
): Promise<void> {
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
