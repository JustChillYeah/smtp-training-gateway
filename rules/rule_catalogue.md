# Rule Catalogue

This document defines the rule-based persuasion cues used by the SMTP training gateway.
Rules are derived from a small, manually curated phishing corpus and are weighted on a 0–5 scale.

## Urgency Rules

### URG_01 – Subject-level urgency keywords
**Tactic:** Urgency  
**Description:** Detects explicit urgency or escalation keywords in the email subject line.  
**Examples:** “URGENT”, “Final Notice”, “Final Reminder”  
**Derived from:** 4/5 urgency corpus emails  
**Weight:** 4  
**Rationale:** Strong indicator of time pressure, but can appear in legitimate emails.

---

### URG_02 – Immediate action language
**Tactic:** Urgency  
**Description:** Detects language demanding immediate action in the email body.  
**Examples:** “as soon as possible”, “immediately”, “you must”, “required to”  
**Derived from:** 5/5 urgency corpus emails  
**Weight:** 3  
**Rationale:** Common urgency signal, but also appears in fear and authority contexts.

---

### URG_03 – Escalation or final-warning framing
**Tactic:** Urgency  
**Description:** Detects escalation language indicating a last opportunity to act.  
**Examples:** “Final Notice”, “Final Reminder”, “Failure to take action will result in…”  
**Derived from:** 3/5 urgency corpus emails  
**Weight:** 5  
**Rationale:** Very strong urgency signal indicating imminent consequences.

---

## Fear Rules

### FER_01 – Explicit threat or harm language
**Tactic:** Fear  
**Description:** Detects direct references to harm, crime, investigation, or personal risk.  
**Examples:** “illegal access”, “identity theft”, “criminal investigation”, “confiscation”, “unauthorised access”, “account at risk”  
**Derived from:** 5/5 fear corpus emails  
**Weight:** 5  
**Rationale:** Very strong fear indicator. These terms frame the recipient as already exposed to harm or legal consequences and rarely appear in benign communications.

---

### FER_02 – Conditional consequence framing
**Tactic:** Fear  
**Description:** Detects conditional statements that escalate harm if the recipient does not act.  
**Examples:** “Failure to do so may result in confiscation”, “Failure to take appropriate steps may place your account at risk”, “Failure to address this matter may delay or prevent access”  
**Derived from:** 4/5 fear corpus emails  
**Weight:** 4  
**Rationale:** Strong fear signal that pressures compliance by threatening worsening outcomes, but slightly weaker than explicit threat language on its own.

---

### FER_03 – Forced remediation after security incident
**Tactic:** Fear  
**Description:** Detects language requiring the recipient to take corrective action following an alleged security incident.  
**Examples:** “review your account activity”, “confirm your information”, “provide documentation”, “complete a security check”  
**Derived from:** 5/5 fear corpus emails  
**Weight:** 3  
**Rationale:** Common follow-up pattern after threat framing. Effective when combined with other fear signals, but weaker in isolation.

---

## Authority Rules

### AUTH_01 – Institutional or governing body reference
**Tactic:** Authority  
**Description:** Detects explicit reference to an institution, regulator, or governing body with formal power over the recipient or their account.  
**Examples:** “HM Revenue & Customs”, “Marketplace Policy Team”, “Safeharbor Department”, “Customer Services”, “Account Review Department”  
**Derived from:** 5/5 authority corpus emails  
**Weight:** 4  
**Rationale:** Strong authority signal based on institutional legitimacy. Effective even without emotional pressure, but may overlap with trusted brands in benign communications.

---

### AUTH_02 – Policy or regulatory framing
**Tactic:** Authority  
**Description:** Detects references to policies, regulations, terms of service, or compliance frameworks used to justify required action.  
**Examples:** “Terms of Service”, “Privacy Policy”, “regulatory requirements”, “policy review”, “guidelines”, “compliance”  
**Derived from:** 4/5 authority corpus emails  
**Weight:** 3  
**Rationale:** Common authority mechanism that frames action as rule-based rather than optional. Weaker in isolation, but reinforces institutional authority when combined with other signals.

---

### AUTH_03 – Mandatory compliance language
**Tactic:** Authority  
**Description:** Detects language indicating that compliance is required rather than optional.  
**Examples:** “you are required to”, “must”, “in order to remain compliant”, “required to confirm”  
**Derived from:** 5/5 authority corpus emails  
**Weight:** 4  
**Rationale:** Strong authority indicator that positions the sender as having the right to demand action. Persuasive even without urgency or explicit threat.

---

## Trust Rules

### TRU_01 – Routine notification framing
**Tactic:** Trust  
**Description:** Detects emails framed as standard informational notices rather than warnings or offers.  
**Examples:** “This message is to inform you”, “Notification”, “Account update”, “Payment receipt”  
**Weight:** 2  
**Rationale:** Common in both phishing and legitimate emails. Lowers suspicion but does not apply pressure.

---

### TRU_02 – Familiar service tone and language
**Tactic:** Trust  
**Description:** Detects neutral, polite, service-oriented language typical of legitimate communications.  
**Examples:** “Thank you”, “Customer Services”, “Do not reply to this email”, “For your information”  
**Weight:** 2  
**Rationale:** Reinforces legitimacy through familiarity. Weak alone, useful in combination.

---

### TRU_03 – Normalised account interaction prompts
**Tactic:** Trust  
**Description:** Detects prompts to perform routine, expected account actions that feel safe.  
**Examples:** “log in to view”, “review your account”, “access online banking”, “view message details”  
**Weight:** 3  
**Rationale:** Encourages habitual behaviour. Stronger than tone alone, but still non-coercive.

---

## Reward Rules

### REW_01 – Refund or money owed to the recipient
**Tactic:** Reward  
**Description:** Detects claims that the recipient is entitled to money due to overpayment or correction of records.  
**Examples:** “tax refund”, “overpayment”, “refund available”, “reimbursements available”  
**Derived from:** HMRC refund example  
**Weight:** 4  
**Rationale:** Strong reward signal based on perceived entitlement to funds. Common in phishing and legitimate contexts, but still highly persuasive.

---

### REW_02 – Lottery or prize win notification
**Tactic:** Reward  
**Description:** Detects claims that the recipient has won a prize or lottery without prior participation.  
**Examples:** “Congratulations”, “you have been selected”, “cash prize”, “winner”  
**Derived from:** Euromillions prize example  
**Weight:** 5  
**Rationale:** Very strong reward signal exploiting excitement and greed. Rare in legitimate email, making it highly indicative.

---

### REW_03 – Disproportionate value exchange
**Tactic:** Reward  
**Description:** Detects framing where a small cost or action results in a much larger financial benefit.  
**Examples:** “9 GBP provides 100 GBP”, “discounted reward card”, “small payment for large credit”  
**Derived from:** Loyalty reward example  
**Weight:** 4  
**Rationale:** Classic reward-based persuasion exploiting value asymmetry. Strong indicator even without urgency or fear.

---

### REW_04 – Inheritance or bequest framing
**Tactic:** Reward  
**Description:** Detects claims that the recipient has been selected to receive inherited or compensation funds.  
**Examples:** “beneficiary”, “bequest”, “funds set aside”, “compensation matters”  
**Derived from:** Bequest notification example  
**Weight:** 4  
**Rationale:** Long-form reward framing promising significant gain. Less immediate than prizes, but still reward-dominant.

---

### REW_05 – Payment or transfer already processed
**Tactic:** Reward  
**Description:** Detects claims that a payment or wire transfer has already been approved or sent to the recipient.  
**Examples:** “wire transfer approved”, “payment processed”, “funds transferred”  
**Derived from:** Wire transfer confirmation example  
**Weight:** 3  
**Rationale:** Moderate reward signal relying on expectation of incoming money. Can overlap with legitimate receipts, so weighted lower.
