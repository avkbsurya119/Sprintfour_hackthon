# Decision Log

Architectural and UX decisions made during the 8-hour hackathon build.

---

## 1. Detector Miss Pattern: Position-Based

**Decision:** Marcus Whitfield (recipient) is caught by detector; Elena Rodriguez (sender) is missed.

**Alternatives considered:**
- Random/arbitrary misses
- Category-based misses (e.g., detector is bad at names generally)

**Why this choice:** Position-based errors tell a better story. Detectors often focus on document headers/recipients and miss sender info buried in signature blocks. This is a realistic failure mode that judges can understand intuitively.

**Tradeoffs:** Slightly more constrained seed data, but creates a memorable "aha" moment when explaining why the miss happened.

---

## 2. Decoy Design: Contextually Labeled

**Decision:** The false-alarm case reference number `847-555-2901` is preceded by "Case Reference" label in the document header.

**Alternatives considered:**
- Unlabeled phone-shaped number (pure regex trap)
- More ambiguous context (e.g., just "Ref: 847-555-2901")

**Why this choice:** A careful reader can distinguish the decoy from real PII by reading context. This tests judgment, not just pattern recognition. The demo beat is stronger: "The risk scorer flagged this, but look — it says 'Case Reference' right there. Sam's job is to catch that the AI missed the context."

**Tradeoffs:** Decoy is "solvable" — a very attentive user will dismiss it correctly. This is intentional; we want to show that humans add value, not that all flags are traps.

---

## 3. Database: SQLite over Postgres

**Decision:** Use SQLite for zero-config single-file storage.

**Alternatives considered:**
- Postgres (more "enterprise-ready")
- In-memory only (even simpler)

**Why this choice:** Postgres adds setup overhead with no demo benefit. SQLite gives us persistent storage for the review session without any configuration. In-memory would lose state on server restart during development.

**Tradeoffs:** Not production-ready, but that's not the goal.

---

## 4. Auth: Skipped Entirely

**Decision:** No authentication, no user model, single implicit reviewer.

**Alternatives considered:**
- Minimal placeholder auth
- Multi-user support with assigned documents

**Why this choice:** Auth adds zero value to the core demo. The problem is "how do we help Sam review better," not "how do we manage multiple Sams."

**Tradeoffs:** Can't demo multi-user scenarios, but those aren't part of the problem statement.

---

## 5. Ground Truth Isolation

**Decision:** Ground truth spans are in a separate table with no direct FK references from other tables. Never exposed via any API endpoint during active review.

**Alternatives considered:**
- Include "is_correct" flags on detector spans (computed from ground truth)
- Expose ground truth in a "debug mode"

**Why this choice:** Leaking correctness info would defeat the demo premise. Sam is supposed to be making judgment calls without knowing the right answer. Ground truth is only used for post-review summary scoring.

**Tradeoffs:** Can't show "you got this one wrong" feedback during review — only aggregate results at end.

---

## 6. Risk Flag Categories: Urgency Tiers

**Decision:** Phone and SSN flags are "critical" urgency; name and email flags are "elevated" urgency.

**Alternatives considered:**
- All risk flags treated equally
- Per-flag confidence scores from the regex matcher

**Why this choice:** SSN and phone exposure is objectively higher-risk than name/email exposure. Visual hierarchy should reflect real-world cost asymmetry. Confidence scores would overcomplicate the UI for marginal benefit.

**Tradeoffs:** Slightly more complex styling, but directly supports the "asymmetric cost" thesis.

---

## 7. Two-Step Dismissal: Staged State is Frontend-Only

**Decision:** "Staged for dismissal" state lives in React state, not persisted to backend.

**Alternatives considered:**
- Persist staged state to database
- Add "staged" as a decision status

**Why this choice:** Simplifies backend, avoids extra API calls. If Sam refreshes mid-review, staged state resets — acceptable for demo scope. The friction mechanism is about forcing a pause, not about audit trails.

**Tradeoffs:** Refresh loses staged state. For an 8-hour build, this is fine.

---

## 8. Span Count Balance: 3 FN / 4 FP / 5 TP

**Decision:** 9 detector spans (5 correct, 4 false positives) + 4 risk flags (3 real catches, 1 decoy).

**Alternatives considered:**
- More items for longer demo
- Fewer items for faster walkthrough

**Why this choice:** 13 total items is reviewable in 2-3 minutes without feeling rushed or padded. Enough variety to show all interaction types (approve, reject, redact, dismiss) without repetition fatigue.

**Tradeoffs:** Demo is tightly scoped — no room for "and here's another example of the same thing."

---

## 9. Document Rendering: Plain Text with Typography

**Decision:** Render document as styled plain text, not formatted letter layout.

**Alternatives considered:**
- Fake letterhead / formatted blocks
- Rich text / markdown rendering

**Why this choice:** Good typography (font, line-height, padding) looks professional without layout complexity. Avoids fiddly CSS for letterhead that adds no demo value.

**Tradeoffs:** Less "realistic" document appearance, but judges will focus on the interaction model, not the stationery.

---

## 10. Span Click Behavior: Scroll-to-Sidebar

**Decision:** Clicking a highlighted span in the document viewer scrolls/focuses the corresponding card in the sidebar.

**Alternatives considered:**
- Inline popover with action buttons
- No click behavior (sidebar-only interaction)

**Why this choice:** Provides useful navigation without complex popover positioning logic. Users can scan the document visually and jump to specific items for action.

**Tradeoffs:** Less "direct manipulation" than inline popovers, but faster to build and less cluttered.

---

# Tier 1: Code Quality & Edge Cases

## 11. Double-Click Protection: Per-Item Submitting State

**Decision:** Track submitting state per item (`Set<string>`) rather than global loading state.

**Alternatives considered:**
- Global isLoading boolean
- Disable all buttons during any submission

**Why this choice:** Per-item tracking allows parallel submissions and only disables the specific item being submitted. Better UX for rapid review sessions.

**Tradeoffs:** Slightly more complex state management, but prevents accidental duplicate submissions without blocking other items.

---

## 12. Decided Cards: Collapsed Single-Line View

**Decision:** Once a decision is made, the card collapses to a single line showing text + badge.

**Alternatives considered:**
- Keep full card layout with disabled buttons
- Hide decided cards entirely

**Why this choice:** Collapsed cards reduce visual noise and let the reviewer focus on remaining items while maintaining visibility of what's been decided.

**Tradeoffs:** Less detail visible for decided items, but the decision badge provides sufficient context.

---

## 13. API Returns Decision ID

**Decision:** `submitDecision` returns the created decision object including its ID.

**Alternatives considered:**
- Return void, don't track IDs
- Separate endpoint to fetch decision IDs

**Why this choice:** Required for undo functionality. The ID is needed to call the DELETE endpoint.

**Tradeoffs:** Slightly larger response payloads, but enables undo without additional API calls.

---

## 14. Undo: Frontend History Stack

**Decision:** Track decision history in React state as a stack of `{decisionId, spanType, spanId, decision}`.

**Alternatives considered:**
- Server-side undo with audit log
- No undo functionality

**Why this choice:** Simple stack-based undo covers the most common case (immediately correcting a misclick). Full audit trail is out of scope for demo.

**Tradeoffs:** History lost on page refresh, but acceptable for demo scope.

---

## 15. Two-Step Dismissal: Deliberate Pause

**Decision:** Dismissing a risk flag requires two clicks (stage → confirm) to add deliberate friction to potentially dangerous decisions.

**Alternatives considered:**
- Single-click dismiss with confirmation modal
- Time-delay before dismiss button becomes active

**Why this choice:** Staged state is visible inline without modal interruption. The visual change (dashed border, warning text) signals "you're about to dismiss a risk flag" without blocking workflow.

**Tradeoffs:** Extra click for legitimate dismissals, but the asymmetric cost model justifies friction on dangerous actions.

---

# Tier 2: Visual Polish & Features

## 16. Enhanced Urgency Tiers: Left Accent Borders

**Decision:** Critical and elevated risk flags have left accent borders (5px/4px) plus subtle shadows.

**Alternatives considered:**
- Top border accent
- Icon-based urgency indicators

**Why this choice:** Left border creates strong visual hierarchy in the sidebar list. Shadow adds depth without overwhelming the card.

**Tradeoffs:** More prominent styling, but urgency tiers should be visually distinct.

---

## 17. Critical Risk Pulse Animation

**Decision:** Undecided critical risk flags have a subtle pulse animation on their box-shadow.

**Alternatives considered:**
- No animation
- Border color pulse
- Icon animation

**Why this choice:** Draws attention to highest-priority items without being distracting. Animation stops once decided.

**Tradeoffs:** Could be seen as excessive, but critical items warrant visual emphasis.

---

## 18. Undo Button: Conditional Display

**Decision:** Undo button only appears when there's at least one decision to undo.

**Alternatives considered:**
- Always show disabled undo button
- Undo as a link instead of button

**Why this choice:** Cleaner footer when no undo is available. Reduces visual noise at start of review.

**Tradeoffs:** Button appearance shifts layout slightly, but the change is minor.

---

## 19. Uploaded Document PII Detection: Option D Confidence-Tier Split

**Decision:** For uploaded documents (PDF/.docx), PII detection results are split across two tiers based on pattern confidence rather than a separate "flawed detector vs. ground truth" model:

- **High-confidence structured patterns** (SSN regex, email regex, phone regex) → `DetectorSpan` rows → appear as "Proposed Redactions" in the sidebar
- **Lower-confidence heuristics** (capitalized name pairs matching a known-first-names list) → `RiskFlag` rows → appear as "Potential Risk - Review Carefully"

No ground truth is stored for uploaded documents. `compute_summary` handles this gracefully: GT-dependent metrics (exposures caught/missed, unnecessary redactions fixed, correct redactions kept) return zero for uploaded documents. `total_reviewed` is always accurate and the complete review flow works end-to-end.

**Alternatives considered:**

- **Option A — Everything → `detector_spans`:** Flattens all urgency tiers. A missed SSN and a possibly-wrong name get the same visual treatment. The "High Risk / Potential Risk" sections disappear for uploaded documents. Unacceptable UX regression.
- **Option B — Random partition:** Creates a fake structural distinction with no semantic meaning. Misleading to the reviewer.
- **Option C — Everything → `risk_flags`:** "Proposed Redactions" section renders empty, looks broken. The approve/reject workflow is bypassed entirely.
- **Option D (chosen) — Split by confidence tier:** Maps directly onto the semantic meaning of the two tiers from the reviewer's perspective: "machine-confident proposed redactions" vs. "things you should double-check."

**Why this choice:** The two tiers in the demo document aren't really "detector vs. risk scorer" from the reviewer's perspective — they're "machine-confident proposed redactions" versus "things you should double-check." Option D maps directly onto that meaning. High-confidence structured patterns have near-zero false positive rates (SSN format is unambiguous, email is structurally identifiable, phone regex is reliable). Name heuristics are prone to false positives — organization names, place names, and honorifics all match the capitalized-word-pair pattern. Splitting on this axis preserves the urgency model and keeps the review UX consistent between demo and uploaded documents.

**On the absence of false-negative simulation for uploads:** For the demo document, a phone number the detector *missed* appears in `risk_flags` as a dangerous catch — because there's a hand-crafted ground truth to miss against. For an uploaded document, a phone number the regex finds goes into `detector_spans` directly. There's no false-negative drama, no "dangerous miss" framing — because there's no hand-crafted ground truth to miss against. The review experience is still complete and correct; it just doesn't have the deliberate pedagogical tension the demo document was designed to create. That's honest, not a gap. Uploaded documents are real, not demo scaffolding.

**Tradeoffs:** The completion summary's GT-dependent metrics (exposures caught/missed) are meaningless for uploaded documents and display as zero. This is disclosed by design — the summary still shows `total_reviewed` accurately, and the core review workflow is fully functional.
