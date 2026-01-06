# NIST 800-30 RISK ASSESSMENT: ENTERPRISE FINANCIAL SYSTEM

**University Financial System Case Study | MSc Cybersecurity Portfolio**  
*Atlantic Technological University, Letterkenny | December 2025*

**Educational Context:** Based on actual ATU'S university infrastructure for realistic application. Technical details sanitized for public sharing. Demonstrates NIST 800-30 risk assessment competency.

---

## PROJECT OVERVIEW

**Objective:** Conduct a comprehensive information security risk assessment of the university's enterprise financial system using NIST SP 800-30 methodology.

**System Assessed:** Banner Finance System
- **Platform:** Red Hat Enterprise Linux
- **Functions:** Financial accounting, HR, payroll processing
- **Users:** Finance personnel, HR staff, payroll administrators, IT support, executive management
- **Data Sensitivity:** Employee PII, salary information, student financial records, bank accounts, medical insurance (GDPR special category)

**Framework:** NIST Special Publication 800-30 Revision 1  
**Duration:** 2 weeks | **Output:** 18-page risk assessment with quantified risk matrices

---

## THE CHALLENGE

**Business Problem:**

University financial system processing sensitive payroll and student billing data facing:
- New BYOD policy implemented without security controls
- No Mobile Device Management (MDM) solution
- Weak password policies below industry standards
- Delayed account deprovisioning for terminated employees
- Untested backup restoration procedures
- Potential GDPR penalties (€20M or 4% revenue)

**Critical System Impact:**
- **Payroll Disruption:** Legal wage payment violations
- **Data Breach:** Employee/student PII exposure (20,000+ records)
- **Financial Fraud:** Unauthorized payment manipulation
- **Operational Shutdown:** Critical business function failure

---

## MY APPROACH

### NIST 800-30 Four-Step Process

**Step 1: Prepare for Assessment**
- Defined organizational context and scope (Banner Finance system)
- Identified stakeholders (IT Executive Director, Security Admin, Operations Supervisor, System Admin, Network Admin)
- Conducted structured interviews with technical and executive staff

**Step 2: Conduct Assessment**
- **IT System Characterization:** Documented hardware, software, data, users, network architecture
- **Threat Identification:** External attackers, insider threats, hardware failures, ransomware
- **Vulnerability Analysis:** Weak passwords, unpatched systems, BYOD gaps, delayed deprovisioning
- **Likelihood Assessment:** Used NIST 5-point scale (Very Low to Very High)
- **Impact Evaluation:** Assessed confidentiality, integrity, availability, financial, operational, reputational impacts
- **Risk Determination:** Applied Likelihood & Impact matrices

**Step 3: Communicate Results**
- Created risk matrices for executive stakeholders
- Prioritized recommendations based on risk levels
- Provided technical findings for IT implementation

**Step 4: Maintain Assessment**
- Recommended ongoing monitoring triggers
- Established annual review schedule
- Defined reassessment criteria (significant changes, major incidents)

---

## KEY DELIVERABLES

### 1. Comprehensive Risk Inventory (9 Risks Identified)

**VERY HIGH Risks (Immediate Action):**
- Weak password configuration (Likelihood: Very High, Impact: Very High)
- Unmanaged BYOD device access (Likelihood: High, Impact: High)
- Unclear network segmentation (Likelihood: High, Impact: Very High)

**HIGH Risks (Urgent Action):**
- Delayed account deprovisioning (Likelihood: Moderate, Impact: High)
- Data leakage via BYOD (Likelihood: High, Impact: Moderate)
- Untested backup restoration (Likelihood: Moderate, Impact: High)

**MODERATE Risks (Timely Remediation):**
- Insufficient change approval (Likelihood: Low, Impact: Moderate)
- Potential unpatched systems (Likelihood: Moderate, Impact: Moderate)

### 2. Risk Assessment Documentation
- Complete IT system characterization (scope, boundaries, components)
- Threat and vulnerability analysis matrices
- NIST likelihood and impact rating tables
- Risk level determination matrices
- Stakeholder interview summaries

### 3. Control Recommendations Mapped to ISO 27001 Annex A
- **A.9.4.3:** Strengthen password policy (12+ characters, complexity, MFA)
- **A.6.2.1:** Deploy MDM for BYOD (device enrollment, encryption, remote wipe)
- **A.13.1.3:** Implement network segmentation (VLANs, firewall rules, NAC)
- **A.9.2.6:** Automate account deprovisioning (HR integration, 1-hour disable)
- **A.12.3.1:** Establish backup testing program (quarterly restoration tests)

### 4. Prioritized Remediation Roadmap
- Risk-based implementation timeline (critical: 7 days, high: 30 days, moderate: 90 days)
- Resource requirements and budget estimates
- Success criteria and metrics
- Risk owner assignments

---

## OUTCOME & VALUES

### Risk Reduction

**Before Assessment:**
- 3 VERY HIGH risks (33% of total)
- 3 HIGH risks (33% of total)
- Unquantified threat exposure
- No prioritized remediation plan

**After Implementing Recommendations:**
- 0 VERY HIGH risks (eliminated through critical controls)
- 2 HIGH risks remaining (reduced from 3)
- Quantified residual risk with acceptance criteria
- Clear remediation roadmap with priorities

**Specific Risk Mitigation:**
- Password weakness → mitigated (MFA + strong policy reduces brute-force likelihood)
- BYOD attack surface → controlled (MDM enforcement, device encryption, remote wipe)
- Network lateral movement → blocked (segmentation prevents compromise spread)
- Terminated employee access → eliminated (automated deprovisioning within 1 hour)

### Regulatory Compliance

**GDPR Article 32 Alignment:**
- Security appropriate to risk (risk-based control selection)
- Encryption recommendations (BYOD devices, backups)
- Confidentiality, integrity, availability controls
- Resilience measures (backup testing, disaster recovery)
- Regular testing procedures (quarterly backups, annual DR simulation)

**Avoided Penalties:**
- Potential €20M GDPR fine
- Legal liability for wage payment disruptions
- Audit findings and remediation costs
- Reputational damage

### OPERATIONAL EFFICIENCY

**Quantified Benefits:**
- Reduced incident response cost (proactive controls cheaper than breach response)
- Faster recovery (documented/tested backup procedures, RTO: 4 hours)
- Automated processes (account deprovisioning: manual → automated)
- Informed decisions (risk matrices enable cost-benefit analysis for security investments)

---

## SKILLS DEMONSTRATED

**Risk Assessment Frameworks:**
- NIST SP 800-30 Rev 1 (complete 4-step process)
- ISO/IEC 27001:2022 (control framework reference)
- ISO/IEC 27005:2022 (risk management)
- GDPR Article 32 (security of processing requirements)

**Core Competencies:**
- IT system characterization and scope definition
- Threat source identification (external, internal, environmental)
- Vulnerability assessment (technical, procedural, people)
- Likelihood determination using probability scales
- Impact analysis across multiple dimensions (CIA, financial, operational, reputational, legal)
- Risk level calculation (likelihood & impact matrices)
- Control selection and gap analysis
- Risk treatment planning (accept, mitigate, transfer, avoid)

**Technical Security:**
- Enterprise system architecture analysis (financial applications)
- Linux security assessment (Red Hat Enterprise)
- Network security architecture review
- Access control analysis (authentication, authorization)
- BYOD security policy evaluation
- Backup and disaster recovery assessment
- Vulnerability research (CVE databases, vendor advisories)

**Stakeholder Management:**
- Structured interviews with technical and executive staff
- Risk communication to non-technical stakeholders
- Prioritized recommendations aligned with business objectives
- Cost-benefit considerations for control selection

---

## KEY LESSONS LEARNED

**Prioritization:** Qualitative "high/medium/low" insufficient for resource allocation. NIST scales (0-10) provide objective comparison. Likelihood & Impact calculation = defensible prioritization.

**Stakeholder Interviews Reveal Hidden Risks:** IT staff knew about weaknesses but lacked formal documentation. Different roles have different risk perspectives. "Assumed" controls often don't exist in practice.

**Recent Changes Create Highest Risks:** BYOD policy was newest vulnerability. IT hadn't fully analyzed security implications. Lack of MDM was "planned for later" but not implemented.

**Control Effectiveness Matters More Than Existence:** ATU had password policy, but it was weak. Backups existed, but weren't tested. Access reviews happened, but inconsistently.

---

**References:** NIST SP 800-30 Rev 1, ISO/IEC 27001:2022, ISO/IEC 27005:2022, GDPR Article 32
