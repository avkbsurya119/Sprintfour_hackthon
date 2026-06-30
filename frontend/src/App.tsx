import React, { useState, useEffect, useCallback, useRef } from 'react';
import './App.css';
import {
  fetchDocument,
  fetchReviewItems,
  submitDecision,
  completeReview,
  deleteDecision,
} from './api';
import type {
  Document,
  DetectorSpan,
  RiskFlag,
  Summary,
  ReviewableItem,
} from './types';

const DOCUMENT_ID = 1;

function getUrgency(flag: RiskFlag): 'critical' | 'elevated' {
  return flag.pii_category === 'phone' || flag.pii_category === 'ssn'
    ? 'critical'
    : 'elevated';
}

// Track decision history for undo
interface DecisionHistoryEntry {
  decisionId: number;
  spanType: 'detector' | 'risk_flag';
  spanId: number;
  decision: string;
}

function App() {
  const [document, setDocument] = useState<Document | null>(null);
  const [detectorSpans, setDetectorSpans] = useState<DetectorSpan[]>([]);
  const [riskFlags, setRiskFlags] = useState<RiskFlag[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [focusedItemId, setFocusedItemId] = useState<string | null>(null);
  const [stagedDismissals, setStagedDismissals] = useState<Set<number>>(new Set());
  const [summary, setSummary] = useState<Summary | null>(null);
  const [submitting, setSubmitting] = useState<Set<string>>(new Set());
  const [decisionHistory, setDecisionHistory] = useState<DecisionHistoryEntry[]>([]);

  const cardRefs = useRef<Map<string, HTMLDivElement>>(new Map());

  // Load data
  useEffect(() => {
    async function loadData() {
      try {
        const [doc, items] = await Promise.all([
          fetchDocument(DOCUMENT_ID),
          fetchReviewItems(DOCUMENT_ID),
        ]);
        setDocument(doc);
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

  // Decision handlers with double-click protection
  const handleDetectorDecision = useCallback(
    async (spanId: number, decision: 'approve' | 'reject') => {
      const key = `detector-${spanId}`;
      if (submitting.has(key)) return;

      setSubmitting((s) => new Set(s).add(key));
      try {
        const result = await submitDecision(DOCUMENT_ID, 'detector', spanId, decision);
        setDetectorSpans((spans) =>
          spans.map((s) => (s.id === spanId ? { ...s, decision } : s))
        );
        setDecisionHistory((h) => [...h, {
          decisionId: result.id,
          spanType: 'detector',
          spanId,
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

    const lastDecision = decisionHistory[decisionHistory.length - 1];
    try {
      await deleteDecision(DOCUMENT_ID, lastDecision.decisionId);

      // Revert UI state
      if (lastDecision.spanType === 'detector') {
        setDetectorSpans((spans) =>
          spans.map((s) =>
            s.id === lastDecision.spanId ? { ...s, decision: null } : s
          )
        );
      } else {
        setRiskFlags((flags) =>
          flags.map((f) =>
            f.id === lastDecision.spanId ? { ...f, decision: null } : f
          )
        );
      }

      // Remove from history
      setDecisionHistory((h) => h.slice(0, -1));
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
  if (!document) return <div className="error">Document not found</div>;

  return (
    <div className="app">
      <header className="header">
        <h1>Conseal Review</h1>
        <span className="header-status">{document.title}</span>
      </header>

      <main className="main-content">
        <DocumentViewer
          content={document.content}
          detectorSpans={detectorSpans}
          riskFlags={riskFlags}
          onSpanClick={handleSpanClick}
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
                      ref={(el) => {
                        if (el) cardRefs.current.set(`risk-${flag.id}`, el);
                      }}
                    />
                  ))}
              </>
            )}

            {/* Detector spans */}
            <div className="section-label">Proposed Redactions</div>
            {detectorSpans.map((span) => (
              <DetectorSpanCard
                key={`detector-${span.id}`}
                span={span}
                isFocused={focusedItemId === `detector-${span.id}`}
                isSubmitting={submitting.has(`detector-${span.id}`)}
                onDecision={handleDetectorDecision}
                ref={(el) => {
                  if (el) cardRefs.current.set(`detector-${span.id}`, el);
                }}
              />
            ))}
          </div>

          <div className="sidebar-footer">
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

      {summary && <CompletionSummary summary={summary} />}
    </div>
  );
}

// Document Viewer Component
interface DocumentViewerProps {
  content: string;
  detectorSpans: DetectorSpan[];
  riskFlags: RiskFlag[];
  onSpanClick: (itemId: string) => void;
}

function DocumentViewer({
  content,
  detectorSpans,
  riskFlags,
  onSpanClick,
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
      urgency: 'standard' as const,
    })),
    ...riskFlags.map((f) => ({
      type: 'risk_flag' as const,
      id: f.id,
      start_offset: f.start_offset,
      end_offset: f.end_offset,
      text_content: f.text_content,
      decision: f.decision,
      pii_category: f.pii_category,
      urgency: getUrgency(f),
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
    const classes = [
      'span-highlight',
      isRiskFlag ? 'risk-flag' : 'detector',
      isRiskFlag ? span.urgency : '',
      span.decision ? 'decided' : '',
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
        <div className="document-title">Document Preview</div>
        <div className="document-text">{elements}</div>
      </div>
    </div>
  );
}

// Detector Span Card Component
interface DetectorSpanCardProps {
  span: DetectorSpan;
  isFocused: boolean;
  isSubmitting: boolean;
  onDecision: (spanId: number, decision: 'approve' | 'reject') => void;
}

const DetectorSpanCard = React.forwardRef<HTMLDivElement, DetectorSpanCardProps>(
  ({ span, isFocused, isSubmitting, onDecision }, ref) => {
    const decided = !!span.decision;

    return (
      <div
        ref={ref}
        className={`review-card detector ${decided ? 'decided' : ''} ${isFocused ? 'focused' : ''}`}
      >
        <div className="card-header">
          <span className="category-label">Proposed redaction</span>
        </div>
        <div className="card-content">{span.text_content}</div>
        {decided ? (
          <div className={`decision-badge ${span.decision}`}>
            {span.decision === 'approve' ? 'Kept redacted' : 'Released'}
          </div>
        ) : (
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
}

const RiskFlagCard = React.forwardRef<HTMLDivElement, RiskFlagCardProps>(
  ({ flag, urgency, isStaged, isFocused, isSubmitting, onAction }, ref) => {
    const decided = !!flag.decision;

    return (
      <div
        ref={ref}
        className={`review-card risk-flag ${urgency} ${decided ? 'decided' : ''} ${isStaged ? 'staged' : ''} ${isFocused ? 'focused' : ''}`}
      >
        <div className="card-header">
          <span className={`urgency-badge ${urgency}`}>
            {urgency === 'critical' ? 'High Risk' : 'Review'}
          </span>
          <span className="category-label">
            Potential {flag.pii_category.toUpperCase()}
          </span>
        </div>
        <div className="card-content">{flag.text_content}</div>

        {isStaged && !decided && (
          <div className="staged-warning">
            Click again to confirm dismissal
          </div>
        )}

        {decided ? (
          <div className={`decision-badge ${flag.decision}`}>
            {flag.decision === 'redact' ? 'Added to redactions' : 'Dismissed'}
          </div>
        ) : (
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
        )}
      </div>
    );
  }
);

// Completion Summary Component
interface CompletionSummaryProps {
  summary: Summary;
}

function CompletionSummary({ summary }: CompletionSummaryProps) {
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
        <button className="btn-restart" onClick={handleRestart}>
          Review Again
        </button>
      </div>
    </div>
  );
}

export default App;
