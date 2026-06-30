import React, { useState, useEffect, useCallback, useRef } from 'react';
import './App.css';
import {
  fetchDocument,
  fetchReviewItems,
  submitDecision,
  completeReview,
  deleteDecision,
  uploadDocument,
  sanitizeDocument,
  createManualSpan,
  updateSpanCategory,
  deleteSpan,
} from './api';
import type {
  SanitizationMode,
  RedactionStyle,
  SanitizeResponse,
  PIICategory,
} from './types';
import type {
  Document,
  DetectorSpan,
  RiskFlag,
  Summary,
  ReviewableItem,
} from './types';

const DEMO_DOCUMENT_ID = 1;

// Available PII categories for manual tagging
const PII_CATEGORIES: { value: PIICategory; label: string }[] = [
  { value: 'name', label: 'Name' },
  { value: 'email', label: 'Email' },
  { value: 'phone', label: 'Phone' },
  { value: 'ssn', label: 'SSN' },
  { value: 'credit_card', label: 'Credit Card' },
  { value: 'location', label: 'Location' },
  { value: 'organization', label: 'Organization' },
  { value: 'date', label: 'Date' },
  { value: 'postal_code', label: 'Postal Code' },
  { value: 'url', label: 'URL' },
  { value: 'username', label: 'Username' },
  { value: 'id_number', label: 'ID Number' },
  { value: 'ip_address', label: 'IP Address' },
  { value: 'money', label: 'Money' },
];

// Workflow stages
type WorkflowStage = 'upload' | 'detecting' | 'review' | 'export';

// Activity log entry for audit trail
interface ActivityLogEntry {
  id: number;
  timestamp: Date;
  action: string;
  details?: string;
  type: 'info' | 'decision' | 'manual' | 'export';
}

// Text selection state for manual PII marking
interface TextSelection {
  start: number;
  end: number;
  text: string;
  rect: DOMRect;
}

function App() {
  const [activeDocumentId, setActiveDocumentId] = useState<number | null>(null);

  if (activeDocumentId === null) {
    return <DocumentPicker onSelect={setActiveDocumentId} />;
  }

  return <ReviewApp documentId={activeDocumentId} onBack={() => setActiveDocumentId(null)} />;
}

function getUrgency(flag: RiskFlag): 'critical' | 'elevated' {
  // Critical: highly sensitive PII that could enable identity theft or fraud
  const criticalCategories = ['ssn', 'phone', 'credit_card', 'ip_address'];
  return criticalCategories.includes(flag.pii_category)
    ? 'critical'
    : 'elevated';
}

// Get urgency for detector spans based on PII category
function getDetectorUrgency(span: DetectorSpan): 'critical' | 'elevated' | 'standard' {
  if (!span.pii_category) return 'standard';
  const criticalCategories = ['ssn', 'credit_card'];
  const elevatedCategories = ['phone', 'email', 'ip_address'];
  if (criticalCategories.includes(span.pii_category)) return 'critical';
  if (elevatedCategories.includes(span.pii_category)) return 'elevated';
  return 'standard';
}

// Get category label for detector spans - use pii_category if available, else infer
function getCategoryLabel(span: DetectorSpan): string {
  // Use the detected category if available
  if (span.pii_category) {
    return span.pii_category.toUpperCase().replace('_', ' ');
  }
  // Fall back to inference for legacy data
  return inferCategory(span.text_content);
}

// Infer category label from text content (fallback for legacy data)
function inferCategory(text: string): string {
  const trimmed = text.trim();

  // SSN pattern: ###-##-####
  if (/^\d{3}-\d{2}-\d{4}$/.test(trimmed)) return 'SSN';

  // Phone pattern: ###-###-####
  if (/^\d{3}-\d{3}-\d{4}$/.test(trimmed)) return 'PHONE';

  // Email pattern
  if (/@/.test(trimmed)) return 'EMAIL';

  // Dollar amount
  if (/^\$[\d,]+(\.\d{2})?$/.test(trimmed)) return 'AMOUNT';

  // Date patterns
  if (/^(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}$/i.test(trimmed)) return 'DATE';

  // Capitalized words (likely names or proper nouns)
  if (/^[A-Z][a-z]+(\s+[A-Z][a-z]+)*$/.test(trimmed)) return 'NAME';
  if (/^[A-Z][a-z]+(\s+(&|and)\s+[A-Z][a-z]+)+/.test(trimmed)) return 'ORG';

  // Multi-word capitalized (organization, court, etc.)
  if (/^([A-Z][a-z]*\s+)+[A-Z][a-z]*$/.test(trimmed)) return 'ORG';

  return 'TEXT';
}

// Track decision history for undo
interface DecisionHistoryEntry {
  decisionId: number;
  spanType: 'detector' | 'risk_flag';
  spanId: number;
  decision: string;
  groupId?: string;  // Links entries that were submitted together (linked spans)
}

// =============================================================================
// Document Picker Screen
// =============================================================================

interface DocumentPickerProps {
  onSelect: (documentId: number) => void;
}

function DocumentPicker({ onSelect }: DocumentPickerProps) {
  const [mode, setMode] = useState<'choose' | 'uploading' | 'error'>('choose');
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(async (file: File) => {
    setMode('uploading');
    setUploadError(null);
    try {
      const result = await uploadDocument(file);
      onSelect(result.document_id);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed');
      setMode('error');
    }
  }, [onSelect]);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(true); };
  const handleDragLeave = () => setIsDragging(false);

  return (
    <div className="picker-screen">
      <div className="picker-card">
        <div className="picker-logo">Conseal</div>
        <h1 className="picker-title">PII Review Tool</h1>
        <p className="picker-subtitle">
          Select a document to review for personally identifiable information.
        </p>

        <div className="picker-options">
          {/* Demo document option */}
          <button
            id="btn-demo-document"
            className="picker-option demo"
            onClick={() => onSelect(DEMO_DOCUMENT_ID)}
            disabled={mode === 'uploading'}
          >
            <div className="picker-option-icon">📋</div>
            <div className="picker-option-body">
              <div className="picker-option-title">Demo Document</div>
              <div className="picker-option-desc">
                A pre-loaded demand letter with deliberately flawed PII detection.
                Includes false positives, false negatives, and a decoy flag.
              </div>
            </div>
            <div className="picker-option-badge">Seeded</div>
          </button>

          {/* Upload option */}
          <div
            id="upload-drop-zone"
            className={`picker-option upload ${isDragging ? 'dragging' : ''} ${mode === 'uploading' ? 'uploading' : ''}`}
            onClick={() => mode !== 'uploading' && fileInputRef.current?.click()}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            <div className="picker-option-icon">
              {mode === 'uploading' ? '⏳' : '📤'}
            </div>
            <div className="picker-option-body">
              <div className="picker-option-title">
                {mode === 'uploading' ? 'Processing…' : 'Upload Your Own'}
              </div>
              <div className="picker-option-desc">
                {mode === 'uploading'
                  ? 'Extracting text and scanning for PII…'
                  : 'PDF or .docx — drag & drop or click to browse. PII is detected automatically.'}
              </div>
            </div>
            <div className="picker-option-badge upload-badge">PDF · DOCX</div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".pdf,.docx"
              style={{ display: 'none' }}
              onChange={handleFileInput}
            />
          </div>
        </div>

        {mode === 'error' && uploadError && (
          <div className="picker-error" id="upload-error-message">
            <span className="picker-error-icon">⚠️</span>
            <div>
              <strong>Upload failed</strong>
              <div className="picker-error-detail">{uploadError}</div>
            </div>
            <button
              className="picker-error-retry"
              onClick={() => { setMode('choose'); setUploadError(null); }}
            >
              Try again
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// =============================================================================
// Review App (existing logic, unchanged — just accepts documentId as prop)
// =============================================================================

interface ReviewAppProps {
  documentId: number;
  onBack: () => void;
}

function ReviewApp({ documentId, onBack }: ReviewAppProps) {
  const DOCUMENT_ID = documentId;
  const [currentDoc, setCurrentDoc] = useState<Document | null>(null);
  const [detectorSpans, setDetectorSpans] = useState<DetectorSpan[]>([]);
  const [riskFlags, setRiskFlags] = useState<RiskFlag[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [focusedItemId, setFocusedItemId] = useState<string | null>(null);
  const [stagedDismissals, setStagedDismissals] = useState<Set<number>>(new Set());
  const [summary, setSummary] = useState<Summary | null>(null);
  const [submitting, setSubmitting] = useState<Set<string>>(new Set());
  const [decisionHistory, setDecisionHistory] = useState<DecisionHistoryEntry[]>([]);
  const [textSelection, setTextSelection] = useState<TextSelection | null>(null);
  const [editingSpan, setEditingSpan] = useState<{ type: 'detector' | 'risk_flag'; id: number } | null>(null);
  const [selectedMode, setSelectedMode] = useState<SanitizationMode>('redact');
  const [selectedStyle, setSelectedStyle] = useState<RedactionStyle>('bars');

  const cardRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const documentTextRef = useRef<HTMLDivElement>(null);

  // Load data
  useEffect(() => {
    async function loadData() {
      try {
        const [doc, items] = await Promise.all([
          fetchDocument(DOCUMENT_ID),
          fetchReviewItems(DOCUMENT_ID),
        ]);
        setCurrentDoc(doc);
        setDetectorSpans(items.detector_spans);
        setRiskFlags(items.risk_flags);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  // Decision handlers with double-click protection and span linking
  const handleDetectorDecision = useCallback(
    async (spanId: number, decision: 'approve' | 'reject') => {
      const key = `detector-${spanId}`;
      if (submitting.has(key)) return;

      // Find all spans with same text_content (linked spans)
      const targetSpan = detectorSpans.find((s) => s.id === spanId);
      if (!targetSpan) return;

      const linkedSpans = detectorSpans.filter(
        (s) => s.text_content === targetSpan.text_content && !s.decision
      );

      // Mark all linked spans as submitting
      const keys = linkedSpans.map((s) => `detector-${s.id}`);
      setSubmitting((s) => {
        const next = new Set(s);
        keys.forEach((k) => next.add(k));
        return next;
      });

      try {
        // Submit decisions for all linked spans
        const results = await Promise.all(
          linkedSpans.map((s) => submitDecision(DOCUMENT_ID, 'detector', s.id, decision))
        );

        // Update all linked spans in UI
        setDetectorSpans((spans) =>
          spans.map((s) =>
            s.text_content === targetSpan.text_content ? { ...s, decision } : s
          )
        );

        // Add all to history (for undo) — tagged with a groupId so undo pops the whole batch
        const groupId = `link-${Date.now()}`;
        setDecisionHistory((h) => [
          ...h,
          ...results.map((result, i) => ({
            decisionId: result.id,
            spanType: 'detector' as const,
            spanId: linkedSpans[i].id,
            decision,
            groupId: linkedSpans.length > 1 ? groupId : undefined,
          })),
        ]);
      } finally {
        setSubmitting((s) => {
          const next = new Set(s);
          keys.forEach((k) => next.delete(k));
          return next;
        });
      }
    },
    [submitting, detectorSpans]
  );

  const handleRiskFlagAction = useCallback(
    async (flagId: number, action: 'redact' | 'stage' | 'confirm-dismiss') => {
      if (action === 'stage') {
        setStagedDismissals((s) => new Set(s).add(flagId));
        return;
      }

      const key = `risk-${flagId}`;
      if (submitting.has(key)) return;

      const decision = action === 'redact' ? 'redact' : 'dismiss';

      setSubmitting((s) => new Set(s).add(key));
      try {
        const result = await submitDecision(DOCUMENT_ID, 'risk_flag', flagId, decision);
        setRiskFlags((flags) =>
          flags.map((f) => (f.id === flagId ? { ...f, decision } : f))
        );
        setStagedDismissals((s) => {
          const next = new Set(s);
          next.delete(flagId);
          return next;
        });
        setDecisionHistory((h) => [...h, {
          decisionId: result.id,
          spanType: 'risk_flag',
          spanId: flagId,
          decision,
        }]);
      } finally {
        setSubmitting((s) => {
          const next = new Set(s);
          next.delete(key);
          return next;
        });
      }
    },
    [submitting]
  );

  const handleComplete = useCallback(async () => {
    try {
      const result = await completeReview(DOCUMENT_ID);
      setSummary(result);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to complete');
    }
  }, []);

  const handleUndo = useCallback(async () => {
    if (decisionHistory.length === 0) return;

    const lastEntry = decisionHistory[decisionHistory.length - 1];

    // Collect all entries in the same group (linked decisions must be undone together)
    const groupEntries = lastEntry.groupId
      ? decisionHistory.filter((e) => e.groupId === lastEntry.groupId)
      : [lastEntry];

    try {
      // Delete all decisions in the group
      await Promise.all(
        groupEntries.map((e) => deleteDecision(DOCUMENT_ID, e.decisionId))
      );

      // Revert UI state for each entry
      const detectorIds = new Set(groupEntries.filter((e) => e.spanType === 'detector').map((e) => e.spanId));
      const riskIds = new Set(groupEntries.filter((e) => e.spanType === 'risk_flag').map((e) => e.spanId));

      if (detectorIds.size > 0) {
        setDetectorSpans((spans) =>
          spans.map((s) => (detectorIds.has(s.id) ? { ...s, decision: null } : s))
        );
      }
      if (riskIds.size > 0) {
        setRiskFlags((flags) =>
          flags.map((f) => (riskIds.has(f.id) ? { ...f, decision: null } : f))
        );
      }

      // Remove the whole group from history
      const groupIdToRemove = lastEntry.groupId;
      setDecisionHistory((h) =>
        groupIdToRemove
          ? h.filter((e) => e.groupId !== groupIdToRemove)
          : h.slice(0, -1)
      );
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to undo');
    }
  }, [decisionHistory]);

  const handleSpanClick = useCallback((itemId: string) => {
    setFocusedItemId(itemId);
    const card = cardRefs.current.get(itemId);
    if (card) {
      card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, []);

  // Handle text selection for manual PII marking
  const handleTextSelection = useCallback(() => {
    const selection = window.getSelection();
    if (!selection || selection.isCollapsed || !documentTextRef.current) {
      setTextSelection(null);
      return;
    }

    const range = selection.getRangeAt(0);
    const selectedText = selection.toString().trim();
    if (!selectedText) {
      setTextSelection(null);
      return;
    }

    // Calculate character offsets from document content
    const docText = documentTextRef.current;
    const preCaretRange = range.cloneRange();
    preCaretRange.selectNodeContents(docText);
    preCaretRange.setEnd(range.startContainer, range.startOffset);
    const startOffset = preCaretRange.toString().length;
    const endOffset = startOffset + selection.toString().length;

    // Get position for toolbar
    const rect = range.getBoundingClientRect();

    setTextSelection({
      start: startOffset,
      end: endOffset,
      text: selectedText,
      rect,
    });
  }, []);

  // Create manual span
  const handleCreateManualSpan = useCallback(
    async (category: PIICategory) => {
      if (!textSelection) return;

      try {
        const result = await createManualSpan(DOCUMENT_ID, {
          start_offset: textSelection.start,
          end_offset: textSelection.end,
          pii_category: category,
          span_type: 'detector',
        });

        // Add the new span to the list
        const newSpan: DetectorSpan = {
          id: result.id,
          start_offset: result.start_offset,
          end_offset: result.end_offset,
          text_content: result.text_content,
          pii_category: result.pii_category,
          confidence_score: 100,
          is_manual: true,
          decision: null,
          ensemble_sources: ['manual'],
          ensemble_agreement_count: 1,
        };

        setDetectorSpans((spans) => [...spans, newSpan].sort((a, b) => a.start_offset - b.start_offset));
        setTextSelection(null);
        window.getSelection()?.removeAllRanges();
      } catch (err) {
        alert(err instanceof Error ? err.message : 'Failed to create span');
      }
    },
    [textSelection, DOCUMENT_ID]
  );

  // Update span category
  const handleUpdateSpanCategory = useCallback(
    async (spanType: 'detector' | 'risk_flag', spanId: number, newCategory: string) => {
      try {
        await updateSpanCategory(DOCUMENT_ID, spanType, spanId, newCategory);

        if (spanType === 'detector') {
          setDetectorSpans((spans) =>
            spans.map((s) => (s.id === spanId ? { ...s, pii_category: newCategory } : s))
          );
        } else {
          setRiskFlags((flags) =>
            flags.map((f) => (f.id === spanId ? { ...f, pii_category: newCategory } : f))
          );
        }
        setEditingSpan(null);
      } catch (err) {
        alert(err instanceof Error ? err.message : 'Failed to update category');
      }
    },
    [DOCUMENT_ID]
  );

  // Delete span
  const handleDeleteSpan = useCallback(
    async (spanType: 'detector' | 'risk_flag', spanId: number) => {
      if (!confirm('Are you sure you want to remove this detection?')) return;

      try {
        await deleteSpan(DOCUMENT_ID, spanType, spanId);

        if (spanType === 'detector') {
          setDetectorSpans((spans) => spans.filter((s) => s.id !== spanId));
        } else {
          setRiskFlags((flags) => flags.filter((f) => f.id !== spanId));
        }
      } catch (err) {
        alert(err instanceof Error ? err.message : 'Failed to delete span');
      }
    },
    [DOCUMENT_ID]
  );

  // Clear selection when clicking elsewhere
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('.selection-toolbar') && !target.closest('.document-text')) {
        setTextSelection(null);
      }
    };
    if (typeof window !== 'undefined' && window.document) {
      window.document.addEventListener('mousedown', handleClickOutside);
      return () => window.document.removeEventListener('mousedown', handleClickOutside);
    }
  }, []);

  // Progress calculations
  const totalItems = detectorSpans.length + riskFlags.length;
  const decidedItems =
    detectorSpans.filter((s) => s.decision).length +
    riskFlags.filter((f) => f.decision).length;
  const progress = totalItems > 0 ? (decidedItems / totalItems) * 100 : 0;
  const pendingRiskFlags = riskFlags.filter((f) => !f.decision).length;
  const allDecided = decidedItems === totalItems;

  if (loading) return <div className="loading">Loading document...</div>;
  if (error) return <div className="error">Error: {error}</div>;
  if (!currentDoc) return <div className="error">Document not found</div>;

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <button className="btn-back" onClick={onBack} title="Back to document picker">
            ← Back
          </button>
          <h1>Conseal Review</h1>
        </div>
        <span className="header-status">{currentDoc.title}</span>
      </header>

      <main className="main-content">
        <DocumentViewer
          content={currentDoc.content}
          detectorSpans={detectorSpans}
          riskFlags={riskFlags}
          onSpanClick={handleSpanClick}
          onTextSelection={handleTextSelection}
          textSelection={textSelection}
          onCreateManualSpan={handleCreateManualSpan}
          onDeleteSpan={handleDeleteSpan}
          editingSpan={editingSpan}
          onEditSpan={setEditingSpan}
          onUpdateCategory={handleUpdateSpanCategory}
          documentTextRef={documentTextRef}
        />

        <aside className="review-sidebar">
          <div className="sidebar-header">
            <h2>Review Items</h2>
            <div className="progress-bar">
              <div className="progress-fill" style={{ width: `${progress}%` }} />
            </div>
            <div className="progress-text">
              <span>
                {decidedItems} of {totalItems} reviewed
              </span>
              {pendingRiskFlags > 0 && (
                <span className="risk-warning">
                  {pendingRiskFlags} risk flag{pendingRiskFlags > 1 ? 's' : ''} pending
                </span>
              )}
            </div>
          </div>

          <div className="sidebar-content">
            {/* Critical risk flags first */}
            {riskFlags.some((f) => getUrgency(f) === 'critical') && (
              <>
                <div className="section-label critical">High Risk - Requires Action</div>
                {riskFlags
                  .filter((f) => getUrgency(f) === 'critical')
                  .map((flag) => (
                    <RiskFlagCard
                      key={`risk-${flag.id}`}
                      flag={flag}
                      urgency="critical"
                      isStaged={stagedDismissals.has(flag.id)}
                      isFocused={focusedItemId === `risk-${flag.id}`}
                      isSubmitting={submitting.has(`risk-${flag.id}`)}
                      onAction={handleRiskFlagAction}
                      onDelete={(id) => handleDeleteSpan('risk_flag', id)}
                      ref={(el) => {
                        if (el) cardRefs.current.set(`risk-${flag.id}`, el);
                      }}
                    />
                  ))}
              </>
            )}

            {/* Elevated risk flags */}
            {riskFlags.some((f) => getUrgency(f) === 'elevated') && (
              <>
                <div className="section-label elevated">Potential Risk - Review Carefully</div>
                {riskFlags
                  .filter((f) => getUrgency(f) === 'elevated')
                  .map((flag) => (
                    <RiskFlagCard
                      key={`risk-${flag.id}`}
                      flag={flag}
                      urgency="elevated"
                      isStaged={stagedDismissals.has(flag.id)}
                      isFocused={focusedItemId === `risk-${flag.id}`}
                      isSubmitting={submitting.has(`risk-${flag.id}`)}
                      onAction={handleRiskFlagAction}
                      onDelete={(id) => handleDeleteSpan('risk_flag', id)}
                      ref={(el) => {
                        if (el) cardRefs.current.set(`risk-${flag.id}`, el);
                      }}
                    />
                  ))}
              </>
            )}

            {/* Detector spans - deduplicated by text_content */}
            <div className="section-label">Proposed Redactions</div>
            {(() => {
              // Group spans by text_content, show one card per unique value
              const seen = new Set<string>();
              const uniqueSpans: Array<{ span: DetectorSpan; count: number }> = [];
              detectorSpans.forEach((span) => {
                if (!seen.has(span.text_content)) {
                  seen.add(span.text_content);
                  const count = detectorSpans.filter(
                    (s) => s.text_content === span.text_content
                  ).length;
                  uniqueSpans.push({ span, count });
                }
              });
              return uniqueSpans.map(({ span, count }) => (
                <DetectorSpanCard
                  key={`detector-${span.id}`}
                  span={span}
                  linkedCount={count}
                  isFocused={focusedItemId === `detector-${span.id}`}
                  isSubmitting={submitting.has(`detector-${span.id}`)}
                  onDecision={handleDetectorDecision}
                  onDelete={(id) => handleDeleteSpan('detector', id)}
                  ref={(el) => {
                    if (el) cardRefs.current.set(`detector-${span.id}`, el);
                  }}
                />
              ));
            })()}
          </div>

          <div className="sidebar-footer">
            {/* Processing Mode Selector */}
            <div className="mode-selector">
              <div className="mode-selector-label">Output Mode:</div>
              <div className="mode-buttons">
                <button
                  className={`mode-btn ${selectedMode === 'redact' ? 'active' : ''}`}
                  onClick={() => setSelectedMode('redact')}
                  title="Replace PII with black bars or [REDACTED]"
                >
                  Redact
                </button>
                <button
                  className={`mode-btn ${selectedMode === 'pseudonymize' ? 'active' : ''}`}
                  onClick={() => setSelectedMode('pseudonymize')}
                  title="Replace PII with consistent labels (PERSON_1, EMAIL_1)"
                >
                  Pseudonymize
                </button>
              </div>
              {selectedMode === 'redact' && (
                <div className="style-buttons">
                  <button
                    className={`style-btn ${selectedStyle === 'bars' ? 'active' : ''}`}
                    onClick={() => setSelectedStyle('bars')}
                  >
                    ████
                  </button>
                  <button
                    className={`style-btn ${selectedStyle === 'brackets' ? 'active' : ''}`}
                    onClick={() => setSelectedStyle('brackets')}
                  >
                    [REDACTED]
                  </button>
                </div>
              )}
            </div>

            {decisionHistory.length > 0 && (
              <button className="btn-undo" onClick={handleUndo}>
                Undo Last Decision
              </button>
            )}
            <button
              className="btn-complete"
              disabled={!allDecided}
              onClick={handleComplete}
            >
              {allDecided ? 'Complete Review' : `${totalItems - decidedItems} items remaining`}
            </button>
          </div>
        </aside>
      </main>

      {summary && (
        <CompletionSummary
          summary={summary}
          documentId={DOCUMENT_ID}
          onBack={onBack}
          initialMode={selectedMode}
          initialStyle={selectedStyle}
        />
      )}
    </div>
  );
}

// Document Viewer Component
interface DocumentViewerProps {
  content: string;
  detectorSpans: DetectorSpan[];
  riskFlags: RiskFlag[];
  onSpanClick: (itemId: string) => void;
  onTextSelection: () => void;
  textSelection: TextSelection | null;
  onCreateManualSpan: (category: PIICategory) => void;
  onDeleteSpan: (spanType: 'detector' | 'risk_flag', spanId: number) => void;
  editingSpan: { type: 'detector' | 'risk_flag'; id: number } | null;
  onEditSpan: (span: { type: 'detector' | 'risk_flag'; id: number } | null) => void;
  onUpdateCategory: (spanType: 'detector' | 'risk_flag', spanId: number, category: string) => void;
  documentTextRef: React.RefObject<HTMLDivElement>;
}

function DocumentViewer({
  content,
  detectorSpans,
  riskFlags,
  onSpanClick,
  onTextSelection,
  textSelection,
  onCreateManualSpan,
  onDeleteSpan,
  editingSpan,
  onEditSpan,
  onUpdateCategory,
  documentTextRef,
}: DocumentViewerProps) {
  // Build list of all spans sorted by position
  const allSpans: ReviewableItem[] = [
    ...detectorSpans.map((s) => ({
      type: 'detector' as const,
      id: s.id,
      start_offset: s.start_offset,
      end_offset: s.end_offset,
      text_content: s.text_content,
      decision: s.decision,
      pii_category: s.pii_category,
      confidence_score: s.confidence_score,
      is_manual: s.is_manual,
      urgency: getDetectorUrgency(s),
      ensemble_sources: s.ensemble_sources,
      ensemble_agreement_count: s.ensemble_agreement_count,
      ensemble_conflict_types: s.ensemble_conflict_types,
    })),
    ...riskFlags.map((f) => ({
      type: 'risk_flag' as const,
      id: f.id,
      start_offset: f.start_offset,
      end_offset: f.end_offset,
      text_content: f.text_content,
      decision: f.decision,
      pii_category: f.pii_category,
      confidence_score: f.confidence_score,
      is_manual: f.is_manual,
      urgency: getUrgency(f),
      ensemble_sources: f.ensemble_sources,
      ensemble_agreement_count: f.ensemble_agreement_count,
      ensemble_conflict_types: f.ensemble_conflict_types,
    })),
  ].sort((a, b) => a.start_offset - b.start_offset);

  // Render content with highlights
  const elements: React.ReactNode[] = [];
  let lastEnd = 0;

  allSpans.forEach((span, idx) => {
    // Text before this span
    if (span.start_offset > lastEnd) {
      elements.push(
        <span key={`text-${idx}`}>{content.slice(lastEnd, span.start_offset)}</span>
      );
    }

    // The highlighted span
    const itemId = `${span.type === 'detector' ? 'detector' : 'risk'}-${span.id}`;
    const isRiskFlag = span.type === 'risk_flag';
    // Redacted = detector approved OR risk flag redacted
    const isRedacted =
      (span.type === 'detector' && span.decision === 'approve') ||
      (span.type === 'risk_flag' && span.decision === 'redact');
    // Released = detector rejected OR risk flag dismissed
    const isReleased =
      (span.type === 'detector' && span.decision === 'reject') ||
      (span.type === 'risk_flag' && span.decision === 'dismiss');
    const classes = [
      'span-highlight',
      isRiskFlag ? 'risk-flag' : 'detector',
      isRiskFlag ? span.urgency : '',
      span.decision ? 'decided' : '',
      isRedacted ? 'redacted' : '',
      isReleased ? 'released' : '',
    ]
      .filter(Boolean)
      .join(' ');

    elements.push(
      <span
        key={`span-${idx}`}
        className={classes}
        onClick={() => onSpanClick(itemId)}
        title={isRiskFlag ? `Potential ${span.pii_category?.toUpperCase()}` : 'Proposed redaction'}
      >
        {content.slice(span.start_offset, span.end_offset)}
      </span>
    );

    lastEnd = span.end_offset;
  });

  // Remaining text
  if (lastEnd < content.length) {
    elements.push(<span key="text-end">{content.slice(lastEnd)}</span>);
  }

  return (
    <div className="document-viewer">
      <div className="document-container">
        <div className="document-title">
          Document Preview
          <span className="document-hint">Select text to mark as PII</span>
        </div>
        <div
          ref={documentTextRef}
          className="document-text"
          onMouseUp={onTextSelection}
        >
          {elements}
        </div>
      </div>

      {/* Text Selection Toolbar */}
      {textSelection && (
        <TextSelectionToolbar
          selection={textSelection}
          onSelectCategory={onCreateManualSpan}
          onClose={() => {
            window.getSelection()?.removeAllRanges();
          }}
        />
      )}
    </div>
  );
}

// Text Selection Toolbar Component
interface TextSelectionToolbarProps {
  selection: TextSelection;
  onSelectCategory: (category: PIICategory) => void;
  onClose: () => void;
}

function TextSelectionToolbar({ selection, onSelectCategory, onClose }: TextSelectionToolbarProps) {
  const [showCategories, setShowCategories] = useState(false);

  // Position the toolbar above the selection
  const style: React.CSSProperties = {
    position: 'fixed',
    top: selection.rect.top - 48,
    left: Math.max(10, selection.rect.left + selection.rect.width / 2 - 100),
    zIndex: 1000,
  };

  return (
    <div className="selection-toolbar" style={style}>
      {!showCategories ? (
        <>
          <span className="selection-text">"{selection.text.slice(0, 20)}{selection.text.length > 20 ? '...' : ''}"</span>
          <button
            className="btn-mark-pii"
            onClick={() => setShowCategories(true)}
          >
            Mark as PII
          </button>
        </>
      ) : (
        <div className="category-selector">
          <div className="category-header">
            <span>Select PII Type:</span>
            <button className="btn-close-categories" onClick={() => setShowCategories(false)}>×</button>
          </div>
          <div className="category-grid">
            {PII_CATEGORIES.map((cat) => (
              <button
                key={cat.value}
                className="category-btn"
                onClick={() => {
                  onSelectCategory(cat.value);
                  onClose();
                }}
              >
                {cat.label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// Detector Span Card Component
interface DetectorSpanCardProps {
  span: DetectorSpan;
  linkedCount: number;  // Number of occurrences with same text_content
  isFocused: boolean;
  isSubmitting: boolean;
  onDecision: (spanId: number, decision: 'approve' | 'reject') => void;
  onDelete?: (spanId: number) => void;
  onEditCategory?: (spanId: number) => void;
}

const DetectorSpanCard = React.forwardRef<HTMLDivElement, DetectorSpanCardProps>(
  ({ span, linkedCount, isFocused, isSubmitting, onDecision, onDelete, onEditCategory }, ref) => {
    const decided = !!span.decision;
    const category = getCategoryLabel(span);
    const isLinked = linkedCount > 1;
    const confidence = span.confidence_score;
    const isManual = span.is_manual;

    return (
      <div
        ref={ref}
        className={`review-card detector ${decided ? 'decided' : ''} ${isFocused ? 'focused' : ''} ${isLinked ? 'linked' : ''}`}
      >
        {decided ? (
          <div className="decided-summary">
            <span className="category-tag">{category}</span>
            {isLinked && (
              <span className="linked-badge" title={`Decision applied to all ${linkedCount} occurrences`}>
                ×{linkedCount}
              </span>
            )}
            <span className={`decided-text ${span.decision === 'approve' ? 'redacted-text' : ''}`}>
              {span.text_content}
            </span>
            <span className={`decision-badge ${span.decision}`}>
              {span.decision === 'approve' ? 'Redacted' : 'Kept Visible'}
            </span>
          </div>
        ) : (
          <>
            <div className="card-header">
              <span className="category-tag">{category}</span>
              <span className="category-label">Proposed redaction</span>
              {isLinked && (
                <span className="linked-badge" title={`Appears ${linkedCount}× — decision applies to all`}>
                  ×{linkedCount}
                </span>
              )}
            </div>
            
            {/* Ensemble Metadata */}
            <div className="ensemble-meta">
              {span.is_manual ? (
                <span className="ensemble-badge manual" title="Manually added by reviewer">
                  ✎ Manually Added
                </span>
              ) : span.ensemble_agreement_count && span.ensemble_agreement_count > 1 ? (
                <span className="ensemble-badge agreement" title={`Detected by: ${span.ensemble_sources?.join(', ')}`}>
                  ✓ Verified by {span.ensemble_agreement_count} detectors
                </span>
              ) : (
                <span className="ensemble-badge single" title={`Detected by: ${span.ensemble_sources?.join(', ')}`}>
                  Caught by {span.ensemble_sources?.[0] || 'regex'}
                </span>
              )}
              {confidence !== undefined && !span.is_manual && (
                <span
                  className={`ensemble-badge confidence ${confidence >= 80 ? 'high' : confidence >= 60 ? 'medium' : 'low'}`}
                  title={`Confidence: ${confidence}%`}
                >
                  {confidence}% conf
                </span>
              )}
              {span.ensemble_conflict_types && span.ensemble_conflict_types.length > 1 && (
                <span className="ensemble-badge conflict" title={`Conflicts: ${span.ensemble_conflict_types.join(' vs ')}`}>
                  ⚠️ Type Mismatch
                </span>
              )}
            </div>

            <div className="card-content">{span.text_content}</div>
            {isLinked && (
              <div className="linked-note">
                Applies to {linkedCount} occurrences in document
              </div>
            )}

            {/* Edit/Delete actions for manual spans */}
            {(isManual || onDelete) && (
              <div className="card-edit-actions">
                {onEditCategory && (
                  <button
                    className="btn-edit-small"
                    onClick={() => onEditCategory(span.id)}
                    title="Change PII category"
                  >
                    Edit Type
                  </button>
                )}
                {onDelete && (
                  <button
                    className="btn-delete-small"
                    onClick={() => onDelete(span.id)}
                    title="Remove this detection"
                  >
                    Remove
                  </button>
                )}
              </div>
            )}

            <div className="card-actions">
              <button
                className="btn btn-approve"
                disabled={isSubmitting}
                onClick={() => onDecision(span.id, 'approve')}
              >
                Keep Redacted
              </button>
              <button
                className="btn btn-reject"
                disabled={isSubmitting}
                onClick={() => onDecision(span.id, 'reject')}
              >
                Release
              </button>
            </div>
          </>
        )}
      </div>
    );
  }
);

// Risk Flag Card Component
interface RiskFlagCardProps {
  flag: RiskFlag;
  urgency: 'critical' | 'elevated';
  isStaged: boolean;
  isFocused: boolean;
  isSubmitting: boolean;
  onAction: (flagId: number, action: 'redact' | 'stage' | 'confirm-dismiss') => void;
  onDelete?: (flagId: number) => void;
}

const RiskFlagCard = React.forwardRef<HTMLDivElement, RiskFlagCardProps>(
  ({ flag, urgency, isStaged, isFocused, isSubmitting, onAction, onDelete }, ref) => {
    const decided = !!flag.decision;
    const confidence = flag.confidence_score;
    const isManual = flag.is_manual;

    return (
      <div
        ref={ref}
        className={`review-card risk-flag ${urgency} ${decided ? 'decided' : ''} ${isStaged ? 'staged' : ''} ${isFocused ? 'focused' : ''}`}
      >
        {decided ? (
          <div className="decided-summary">
            <span className={`urgency-badge ${urgency}`}>
              {urgency === 'critical' ? 'High' : 'Review'}
            </span>
            <span className={`decided-text ${flag.decision === 'redact' ? 'redacted-text' : ''}`}>
              {flag.text_content}
            </span>
            <span className={`decision-badge ${flag.decision}`}>
              {flag.decision === 'redact' ? 'Redacted' : 'Dismissed'}
            </span>
          </div>
        ) : (
          <>
            <div className="card-header">
              <span className={`urgency-badge ${urgency}`}>
                {urgency === 'critical' ? 'High Risk' : 'Review'}
              </span>
              <span className="category-label">
                Potential {flag.pii_category.toUpperCase()}
              </span>
            </div>
            
            {/* Ensemble Metadata */}
            <div className="ensemble-meta">
              {flag.is_manual ? (
                <span className="ensemble-badge manual" title="Manually added by reviewer">
                  ✎ Manually Added
                </span>
              ) : flag.ensemble_agreement_count && flag.ensemble_agreement_count > 1 ? (
                <span className="ensemble-badge agreement" title={`Detected by: ${flag.ensemble_sources?.join(', ')}`}>
                  ✓ Verified by {flag.ensemble_agreement_count} detectors
                </span>
              ) : (
                <span className="ensemble-badge single" title={`Detected by: ${flag.ensemble_sources?.join(', ')}`}>
                  Caught by {flag.ensemble_sources?.[0] || 'regex'}
                </span>
              )}
              {confidence !== undefined && !flag.is_manual && (
                <span
                  className={`ensemble-badge confidence ${confidence >= 80 ? 'high' : confidence >= 60 ? 'medium' : 'low'}`}
                  title={`Confidence: ${confidence}%`}
                >
                  {confidence}% conf
                </span>
              )}
              {flag.ensemble_conflict_types && flag.ensemble_conflict_types.length > 1 && (
                <span className="ensemble-badge conflict" title={`Conflicts: ${flag.ensemble_conflict_types.join(' vs ')}`}>
                  ⚠️ Type Mismatch
                </span>
              )}
            </div>

            <div className="card-content">{flag.text_content}</div>

            {/* Delete action for manual flags */}
            {(isManual || onDelete) && onDelete && (
              <div className="card-edit-actions">
                <button
                  className="btn-delete-small"
                  onClick={() => onDelete(flag.id)}
                  title="Remove this detection"
                >
                  Remove
                </button>
              </div>
            )}

            {isStaged && (
              <div className="staged-warning">
                Click again to confirm dismissal
              </div>
            )}

            <div className="card-actions">
              <button
                className="btn btn-redact"
                disabled={isSubmitting}
                onClick={() => onAction(flag.id, 'redact')}
              >
                Redact This
              </button>
              {isStaged ? (
                <button
                  className="btn btn-confirm-dismiss"
                  disabled={isSubmitting}
                  onClick={() => onAction(flag.id, 'confirm-dismiss')}
                >
                  Confirm Dismiss
                </button>
              ) : (
                <button
                  className="btn btn-dismiss"
                  disabled={isSubmitting}
                  onClick={() => onAction(flag.id, 'stage')}
                >
                  Dismiss
                </button>
              )}
            </div>
          </>
        )}
      </div>
    );
  }
);

// Sanitization Panel Component
interface SanitizationPanelProps {
  documentId: number;
  initialMode?: SanitizationMode;
  initialStyle?: RedactionStyle;
}

function SanitizationPanel({ documentId, initialMode = 'redact', initialStyle = 'bars' }: SanitizationPanelProps) {
  const [mode, setMode] = useState<SanitizationMode>(initialMode);
  const [redactionStyle, setRedactionStyle] = useState<RedactionStyle>(initialStyle);
  const [isProcessing, setIsProcessing] = useState(false);
  const [result, setResult] = useState<SanitizeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSanitize = async () => {
    setIsProcessing(true);
    setError(null);
    try {
      const response = await sanitizeDocument(documentId, {
        mode,
        redaction_style: mode === 'redact' ? redactionStyle : undefined,
      });
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sanitization failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDownload = () => {
    if (!result) return;
    const blob = new Blob([result.content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sanitized_document_${documentId}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopyToClipboard = () => {
    if (!result) return;
    navigator.clipboard.writeText(result.content);
  };

  return (
    <div className="sanitization-panel">
      <h3>Export Sanitized Document</h3>

      {!result ? (
        <>
          <div className="sanitization-options">
            <div className="option-group">
              <label>Sanitization Mode</label>
              <div className="radio-group">
                <label className={`radio-option ${mode === 'redact' ? 'selected' : ''}`}>
                  <input
                    type="radio"
                    name="mode"
                    value="redact"
                    checked={mode === 'redact'}
                    onChange={() => setMode('redact')}
                  />
                  <span className="radio-label">
                    <strong>Redact</strong>
                    <span className="radio-desc">Replace PII with ████ or [REDACTED]</span>
                  </span>
                </label>
                <label className={`radio-option ${mode === 'pseudonymize' ? 'selected' : ''}`}>
                  <input
                    type="radio"
                    name="mode"
                    value="pseudonymize"
                    checked={mode === 'pseudonymize'}
                    onChange={() => setMode('pseudonymize')}
                  />
                  <span className="radio-label">
                    <strong>Pseudonymize</strong>
                    <span className="radio-desc">Replace with consistent labels (PERSON_1, EMAIL_1)</span>
                  </span>
                </label>
              </div>
            </div>

            {mode === 'redact' && (
              <div className="option-group">
                <label>Redaction Style</label>
                <div className="radio-group">
                  <label className={`radio-option ${redactionStyle === 'bars' ? 'selected' : ''}`}>
                    <input
                      type="radio"
                      name="style"
                      value="bars"
                      checked={redactionStyle === 'bars'}
                      onChange={() => setRedactionStyle('bars')}
                    />
                    <span className="radio-label">
                      <strong>Black Bars</strong>
                      <span className="radio-desc">████████████</span>
                    </span>
                  </label>
                  <label className={`radio-option ${redactionStyle === 'brackets' ? 'selected' : ''}`}>
                    <input
                      type="radio"
                      name="style"
                      value="brackets"
                      checked={redactionStyle === 'brackets'}
                      onChange={() => setRedactionStyle('brackets')}
                    />
                    <span className="radio-label">
                      <strong>Brackets</strong>
                      <span className="radio-desc">[REDACTED]</span>
                    </span>
                  </label>
                </div>
              </div>
            )}
          </div>

          <button
            className="btn-sanitize"
            onClick={handleSanitize}
            disabled={isProcessing}
          >
            {isProcessing ? 'Processing...' : 'Generate Sanitized Document'}
          </button>

          {error && <div className="sanitization-error">{error}</div>}
        </>
      ) : (
        <div className="sanitization-result">
          <div className="result-header">
            <span className="result-mode">
              {result.mode === 'redact' ? 'Redacted' : 'Pseudonymized'}
            </span>
            <span className="result-count">
              {result.redaction_count} item{result.redaction_count !== 1 ? 's' : ''} processed
            </span>
          </div>

          <div className="result-preview">
            <pre>{result.content.slice(0, 500)}{result.content.length > 500 ? '...' : ''}</pre>
          </div>

          {result.mode === 'pseudonymize' && result.pseudonym_mapping && (
            <div className="pseudonym-mapping">
              <h4>Pseudonym Mapping</h4>
              <div className="mapping-table">
                {Object.entries(result.pseudonym_mapping).map(([original, pseudonym]) => (
                  <div key={original} className="mapping-row">
                    <span className="mapping-original">{original}</span>
                    <span className="mapping-arrow">→</span>
                    <span className="mapping-pseudonym">{pseudonym}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="result-actions">
            <button className="btn-download" onClick={handleDownload}>
              Download
            </button>
            <button className="btn-copy" onClick={handleCopyToClipboard}>
              Copy to Clipboard
            </button>
            <button className="btn-regenerate" onClick={() => setResult(null)}>
              Regenerate
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// Completion Summary Component
interface CompletionSummaryProps {
  summary: Summary;
  documentId: number;
  onBack: () => void;
  initialMode?: SanitizationMode;
  initialStyle?: RedactionStyle;
}

function CompletionSummary({ summary, documentId, onBack, initialMode, initialStyle }: CompletionSummaryProps) {
  const handleRestart = () => {
    window.location.reload();
  };

  return (
    <div className="summary-overlay">
      <div className="summary-card">
        <h2>Review Complete</h2>
        <div className="summary-stats">
          <div className="stat-row good">
            <span className="stat-label">PII exposures caught</span>
            <span className="stat-value">{summary.exposures_caught}</span>
          </div>
          <div className={`stat-row ${summary.exposures_missed > 0 ? 'bad' : 'good'}`}>
            <span className="stat-label">PII exposures missed</span>
            <span className="stat-value">{summary.exposures_missed}</span>
          </div>
          <div className="stat-row good">
            <span className="stat-label">Unnecessary redactions fixed</span>
            <span className="stat-value">{summary.unnecessary_redactions_fixed}</span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Correct redactions kept</span>
            <span className="stat-value">{summary.correct_redactions_kept}</span>
          </div>
        </div>
        <div className="summary-message">
          {summary.exposures_missed === 0
            ? 'Great work! You caught all the PII exposures the detector missed.'
            : `${summary.exposures_missed} potential PII exposure${summary.exposures_missed > 1 ? 's were' : ' was'} left unaddressed.`}
        </div>

        <SanitizationPanel
          documentId={documentId}
          initialMode={initialMode}
          initialStyle={initialStyle}
        />

        <div className="summary-actions">
          <button className="btn-restart" onClick={handleRestart}>
            Review Again
          </button>
          <button className="btn-back-to-picker" onClick={onBack}>
            ← Choose Another Document
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;
