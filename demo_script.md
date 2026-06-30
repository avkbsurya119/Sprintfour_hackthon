# Conseal: Demo Video Script
**Target Length:** ~2.5 to 3 Minutes
**Pacing:** Keep it energetic. Show, don't just tell.

---

## 1. The Hook & The Problem (0:00 - 0:30)
**[Visual: Start on the gorgeous WebGL Ribbons Landing Page. Slowly move your mouse to show it's interactive.]**

**You say:** 
> "Hi, I'm [Your Name], and this is **Conseal**. We built this to solve Problem 3: fixing the mistakes made by automated PII detectors. 
> 
> Reviewers processing automated redactions face two types of errors: *False Positives*, which are annoying but harmless, and *False Negatives*—where dangerous PII is missed entirely. 
> 
> Traditional UIs treat both errors exactly the same, causing reviewers to skim and accidentally approve dangerous data leaks. Conseal fixes this through a concept we call **Asymmetric Friction**."

*[Click "Start Review" and enter the demo document]*

---

## 2. The Solution: Visual Hierarchy & Asymmetric Friction (0:30 - 1:30)
**[Visual: Show the main review UI. Point to the 'Proposed Redactions' (gray) vs 'Potential Risks' (red/orange) in the sidebar.]**

**You say:**
> "When the document loads, you instantly notice our visual risk hierarchy. Standard, high-confidence redactions are grouped at the bottom in gray. Approving these is a lightning-fast, single-click action." 
> 
> *[Action: Quickly click "Keep Redacted" on a few of the gray 'Proposed Redactions' to show how fast it is.]*

> "But up top, we have our 'Potential Risks'. Our backend uses a specialized ensemble 'second-pass' scanner to actively hunt for PII the primary detector missed. 
> 
> Notice this red Critical Risk flag for a phone number. If I try to dismiss this, I can't just click once. I have to 'Stage' it, and then explicitly 'Confirm' it."
> 
> *[Action: Click 'Dismiss' on a red risk flag. Show how it turns into a blue 'Confirm Dismissal' button. Then click confirm.]*

> "This two-step process forces deliberate friction for dangerous decisions, preventing accidental data leaks, while keeping safe actions fast."

---

## 3. The Smart Engine & Edge Cases (1:30 - 2:00)
**[Visual: Highlight the specific edge cases in the text, like the ALL CAPS name or the email without a TLD.]**

**You say:**
> "Under the hood, our ensemble detector combines spaCy, Microsoft Presidio, and custom regex to catch real-world OCR anomalies. 
> 
> For example, it intelligently caught this malformed email address missing a '.com', and this ALL CAPS Indian name that standard ML models almost always ignore. 
> 
> We also added smart deduplication. Notice how if I make a decision on one item, it automatically applies to all identical occurrences in the document."

---

## 4. Extra Polish & The Finale (2:00 - 2:30)
**[Visual: Highlight a random word in the text with your cursor to trigger the manual tagger.]**

**You say:**
> "Reviewers also have complete control. You can manually highlight any unflagged text and instantly tag it. And if you make a mistake? Every card has an inline 'Reset' button, or you can use the global 'Reset All' switch at the bottom to wipe the slate clean."
> 
> *[Action: Click 'Complete Review' to bring up the final summary modal]*

> "Finally, instead of a gamified accuracy percentage, our completion screen forces a security mindset by showing exactly how many 'Exposures were Caught' versus 'Exposures Missed'. 
> 
> This is Conseal—a truly secure, friction-based review experience."
