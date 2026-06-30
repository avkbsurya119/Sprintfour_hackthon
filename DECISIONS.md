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
