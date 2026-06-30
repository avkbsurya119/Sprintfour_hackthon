# Conseal: Hackathon Submission Writeup

### What I Built
I built **Conseal**, a smart, friction-based correction review interface designed to solve a specific, high-stakes problem: **alert fatigue in PII redaction.** 

When reviewers process AI-suggested redactions, they face two types of errors: *false positives* (annoying, but harmless) and *false negatives* (dangerous data exposures). Because traditional UIs treat both errors with the exact same visual weight, reviewers inevitably skim past dangerous misses. 

To solve this, I built a system centered around **Asymmetric Friction** and a **Visual Risk Hierarchy**. I implemented a custom ensemble "second-pass" risk scorer (combining spaCy, Microsoft Presidio, and highly specialized edge-case Regex for things like ALL CAPS text and malformed emails) to actively hunt for PII that the primary detector missed. 

When a potential miss is found, it's injected into the UI as a "Risk Flag" (Critical or Elevated). Crucially, dismissing these dangerous flags requires a deliberate, two-step action (Stage -> Confirm), forcing the reviewer to pause. Meanwhile, approving routine, high-confidence redactions remains a lightning-fast, single-click action. I wrapped this entire workflow in a premium, highly polished interface featuring a custom 3D WebGL Ribbons landing page, inline correction resetting, and smart text deduplication.

### What I Intentionally Chose NOT to Build
To ensure my 8-hour hackathon build remained laser-focused on the core interaction problem, I made several ruthless scoping decisions:

1. **User Authentication & Multi-Tenant Support:** I skipped auth entirely. The problem I was solving was *"how do I help Sam review better,"* not *"how do I manage multiple Sams."* Building login screens would have consumed time with zero demo value.
2. **Complex Database Infrastructure:** I chose SQLite over Postgres. I needed zero-configuration, single-file persistence so judges and users could run the project instantly without spinning up Docker containers or database servers.
3. **Rich Text / Complex Document Rendering:** I chose to render the documents as carefully styled plain text rather than building a complex PDF or rich-text layout engine. Clean typography looks professional, and complex layout code would have distracted from the actual review UX.
4. **Backend State for "Staged" Dismissals:** The intermediate "staged" state for my two-step dismissal lives entirely in the frontend React state. If a user refreshes, the staged state is lost. This kept the API incredibly fast and simple, prioritizing the real-time review experience over rigid audit trails.
5. **Leaking Ground Truth Data:** I strictly isolated the ground truth data from the frontend during the active review process. I didn't build "hints" or "is_correct" flags into the detector payload because I wanted the reviewer to experience the genuine tension of making judgment calls without knowing the right answer until the final summary screen.
