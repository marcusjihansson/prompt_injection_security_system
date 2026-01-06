# OWASP Top 10 for LLM Applications - Comprehensive Overview

## About the OWASP Project

The **OWASP Top 10 for Large Language Model Applications** is a community-driven initiative part of the broader OWASP GenAI Security Project. It aims to identify and address the most critical security vulnerabilities specific to applications utilizing Large Language Models and generative AI systems.

### Mission

The project's mission is to make LLM application security visible, enabling people and organizations to make informed decisions about security risks. While sharing similarities with other OWASP Top 10 lists, this project specifically explores how conventional vulnerabilities manifest uniquely in LLM applications and how traditional remediation strategies must be adapted.

### Project Background

- **Founded:** May 2023
- **First Release:** August 2023 (Version 1.0)
- **Updated:** October 2023 (Version 1.1)
- **Latest Release:** November 2024 (Version 2025)
- **Contributors:** 600+ experts from 18+ countries
- **Community Members:** Nearly 8,000 active participants
- **Initial Contributors:** The first version was contributed by Steve Wilson of Contrast Security

### Target Audience

The primary audience includes:

- Software developers
- Data scientists and ML engineers
- Security professionals
- CISOs and compliance officers
- AI practitioners
- Policymakers

## Complete Vulnerability List Comparison

### OWASP Top 10 for LLM Applications: 2023-24 vs 2025

| Rank | 2023-24 Version                      | 2025 Version                         | Status                     |
| ---- | ------------------------------------ | ------------------------------------ | -------------------------- |
| #1   | **Prompt Injection**                 | **Prompt Injection**                 | ✓ Retained at #1           |
| #2   | **Insecure Output Handling**         | **Sensitive Information Disclosure** | ↑ Moved from #6            |
| #3   | **Training Data Poisoning**          | **Supply Chain Vulnerabilities**     | ↑ Moved from #5            |
| #4   | **Model Denial of Service**          | **Data and Model Poisoning**         | ↓ Moved from #3, renamed   |
| #5   | **Supply Chain Vulnerabilities**     | **Improper Output Handling**         | ↓ Moved from #2, renamed   |
| #6   | **Sensitive Information Disclosure** | **Excessive Agency**                 | ↑ Moved from #8            |
| #7   | **Insecure Plugin Design**           | **System Prompt Leakage**            | ✗ Removed / ✓ New category |
| #8   | **Excessive Agency**                 | **Vector and Embedding Weaknesses**  | ✗ / ✓ New category         |
| #9   | **Overreliance**                     | **Misinformation**                   | ≈ Renamed and expanded     |
| #10  | **Model Theft**                      | **Unbounded Consumption**            | ↓ Moved from #4, expanded  |

### Summary of Major Changes

**Removed from Top 10:**

- **Insecure Plugin Design** (LLM07:2023) - Consolidated into other categories
- **Model Denial of Service** (as standalone) - Evolved into Unbounded Consumption
- **Model Theft** (LLM10:2023) - Moved to #10 in 2025 but renamed to Unbounded Consumption

**Added to Top 10:**

- **System Prompt Leakage** (LLM07:2025) - New standalone category
- **Vector and Embedding Weaknesses** (LLM08:2025) - New category for RAG systems

**Significantly Reranked:**

- **Sensitive Information Disclosure**: #6 → #2 (Major rise)
- **Supply Chain Vulnerabilities**: #5 → #3 (Significant rise)
- **Excessive Agency**: #8 → #6 (Rise)

## Project Evolution: 2023 vs 2025

### Key Changes Between Versions

The 2025 version represents significant evolution based on real-world incidents, deployment lessons, and emerging attack techniques observed over two years of LLM deployment in production environments.

#### New Vulnerabilities Added in 2025

1. **System Prompt Leakage** (LLM07:2025)
   - Added in response to numerous real-world incidents
   - Occurs when LLMs inadvertently reveal internal instructions or system prompts
   - Enables attackers to craft more sophisticated attacks

2. **Vector and Embedding Weaknesses** (LLM08:2025)
   - Added to address RAG (Retrieval-Augmented Generation) security concerns
   - 53% of companies rely on RAG instead of fine-tuning
   - Addresses vulnerabilities in embedding-based methods

#### Vulnerabilities Removed or Consolidated in 2025

1. **Insecure Plugin Design** (was LLM07:2023)
   - Removed as a standalone category
   - Risks now encompassed within Excessive Agency and other categories
   - Reflects shift toward systematic defenses

2. **Model Theft** (was LLM10:2023)
   - No longer a standalone category
   - Risks now covered under Unbounded Consumption

#### Significant Ranking Changes

| Vulnerability                    | 2023-24 Rank | 2025 Rank | Change                                                     |
| -------------------------------- | ------------ | --------- | ---------------------------------------------------------- |
| Sensitive Information Disclosure | #6           | #2        | ↑↑↑↑ Major Rise                                            |
| Supply Chain Vulnerabilities     | #5           | #3        | ↑↑ Significant Rise                                        |
| Excessive Agency                 | #8           | #6        | ↑↑ Rise                                                    |
| Training Data Poisoning          | #3           | #4        | ↓ Slight Drop (renamed to Data and Model Poisoning)        |
| Insecure Output Handling         | #2           | #5        | ↓↓↓ Significant Drop (renamed to Improper Output Handling) |

#### Updated and Expanded Categories

1. **Unbounded Consumption** (formerly "Denial of Service")
   - Expanded to include resource management risks
   - Addresses "Denial of Wallet" concerns in cloud environments
   - Covers unexpected operational costs

2. **Misinformation** (formerly "Overreliance")
   - Expanded to emphasize risks of treating LLM outputs as absolute truth
   - Addresses hallucinations and fabricated information
   - Includes lack of proper oversight mechanisms

3. **Excessive Agency**
   - Expanded to recognize risks of unchecked permissions
   - Reflects the emergence of autonomous AI agents
   - 2025 recognized as the "year of LLM agents"

## OWASP Top 10 for LLM Applications (2023-24 Version)

For historical reference, here is the complete list from the 2023-24 version (v1.1):

### LLM01:2023 - Prompt Injection

Manipulating LLM behavior through crafted inputs that bypass original instructions. Attackers could directly manipulate the LLM or use indirect methods through external content.

### LLM02:2023 - Insecure Output Handling

Insufficient validation, sanitization, and handling of LLM-generated content before passing it to downstream systems, leading to code injection, XSS, and other vulnerabilities.

### LLM03:2023 - Training Data Poisoning

Manipulation of training data that impairs model performance, leading to responses that compromise security, accuracy, or ethical behavior.

### LLM04:2023 - Model Denial of Service

Resource exhaustion attacks where attackers interact with LLMs in ways that consume excessive resources, causing service disruptions and increased costs.

### LLM05:2023 - Supply Chain Vulnerabilities

Compromised components, services, or datasets that undermine system integrity, causing data breaches and system failures.

### LLM06:2023 - Sensitive Information Disclosure

LLM applications revealing sensitive information, proprietary algorithms, or confidential data in their outputs, resulting in legal consequences or loss of competitive advantage.

### LLM07:2023 - Insecure Plugin Design

LLM plugins with insufficient access control and validation, enabling severe exploits like remote code execution when processing untrusted inputs.

### LLM08:2023 - Excessive Agency

Granting LLMs excessive autonomy to take actions without proper oversight, leading to unintended consequences that jeopardize reliability, privacy, and trust.

### LLM09:2023 - Overreliance

Failing to critically assess LLM outputs, leading to compromised decision-making, security vulnerabilities, and legal liabilities when erroneous information is produced.

### LLM10:2023 - Model Theft

Unauthorized access to proprietary large language models, risking theft of intellectual property, competitive advantage, and dissemination of sensitive information.

---

## OWASP Top 10 for LLM Applications (2025)

### LLM01:2025 - Prompt Injection

**Description:** Manipulating LLM behavior through crafted inputs that bypass original instructions.

**Types:**

- **Direct Prompt Injection:** Attacker directly manipulates the LLM through malicious prompts
- **Indirect Prompt Injection:** Malicious instructions embedded in external content (websites, documents)

**Impact:** Unauthorized access, data breaches, compromised decision-making

**Example Attack Scenarios:**

- Social engineering to extract sensitive information
- Bypassing content filters and safety guardrails
- Executing unauthorized actions through tool integrations

**Prevention:**

- Implement strict input validation
- Use separate contexts for system instructions and user inputs
- Apply privilege controls on LLM access
- Monitor and log all LLM interactions

---

### LLM02:2025 - Sensitive Information Disclosure

**Description:** Failure to protect against disclosure of confidential data in LLM outputs, including exposure of training data, system prompts, or user information.

**Why the Major Rise:** Growing concerns as organizations increasingly use LLMs with sensitive data. Staff misuse by inputting confidential information (PII, IP) that can appear in responses to other users or through data breaches.

**Impact:** Legal consequences, loss of competitive advantage, privacy violations, regulatory penalties

**Example Attack Scenarios:**

- LLM reveals PII from training data
- Exposure of proprietary business information
- Leakage of authentication credentials or API keys

**Prevention:**

- Implement data sanitization on inputs and outputs
- Define and enforce sensitive data categories
- Use data loss prevention (DLP) tools
- Apply user awareness training
- Ensure transparency in data usage policies
- Consider homomorphic encryption for sensitive data

---

### LLM03:2025 - Supply Chain Vulnerabilities

**Description:** Compromised components, models, datasets, or dependencies that undermine system integrity.

**Why the Rise:** Once theoretical in 2023, now concrete examples exist of poisoned models and tainted datasets causing real-world disruptions. Multiple attack vectors have been observed.

**Common Risks:**

- **Data Poisoning:** Malicious manipulation of training data
- **Model Tampering:** Compromised third-party models with backdoors
- **Fine-tuning Risks:** Vulnerabilities in LoRA, PEFT techniques
- **On-Device LLMs:** Expanded attack surface
- **Dependency Vulnerabilities:** Compromised libraries and frameworks

**Real-World Examples:**

- PyPi package registry attacks (PyTorch compromise)
- PoisonGPT attack bypassing Hugging Face safety features
- Shadow Ray attack on Ray AI framework
- LeftOvers GPU memory exploitation

**Prevention:**

- Conduct thorough supplier assessments
- Implement model versioning and integrity checks
- Use only vetted, signed models and datasets
- Apply SBOM (Software Bill of Materials)
- Maintain vulnerability scanning pipelines
- Implement anomaly detection for model behavior

---

### LLM04:2025 - Data and Model Poisoning

**Description:** Tampered training data or manipulated models that impair performance, leading to compromised security, accuracy, or ethical behavior.

**Impact:** Biased outputs, harmful responses, backdoors, degraded model performance

**Attack Vectors:**

- Injecting malicious data into training sets
- Manipulating fine-tuning datasets
- Direct model tampering
- Embedding backdoors during training

**Prevention:**

- Verify training data sources
- Implement data validation and sanitization
- Use anomaly detection on training data
- Apply robust testing across diverse scenarios
- Maintain data provenance tracking
- Monitor model behavior post-deployment

---

### LLM05:2025 - Improper Output Handling

**Description:** Insufficient validation, sanitization, and handling of LLM-generated content before passing it to downstream systems.

**Impact:** Code injection, cross-site scripting (XSS), remote code execution, system compromise

**Example Attack Scenarios:**

- LLM output containing malicious JavaScript executed in browser
- SQL injection through unsanitized LLM-generated queries
- Command injection in system calls
- CSRF attacks through crafted responses

**Prevention:**

- Treat LLM outputs as untrusted user input
- Apply zero-trust principles
- Implement robust output validation and sanitization
- Use parameterized queries and prepared statements
- Follow OWASP ASVS guidelines for output handling
- Encode outputs appropriately for context

---

### LLM06:2025 - Excessive Agency

**Description:** Granting LLMs unchecked autonomy with overly permissive capabilities and permissions to interact with systems and execute actions.

**Why Expanded:** Recognition of autonomous AI agents becoming prevalent in 2025. Increased risk as LLMs make decisions about tool usage dynamically.

**Impact:** Unintended consequences, data breaches, financial losses, reputational damage, system compromise

**Example Attack Scenarios:**

- LLM agent accessing unauthorized databases
- Executing privileged operations without approval
- Making financial transactions beyond intended scope
- Deleting or modifying critical data

**Prevention:**

- Implement principle of least privilege
- Require human-in-the-loop for sensitive actions
- Use granular permission controls
- Implement operation allowlists (not blocklists)
- Apply transaction limits and rate limiting
- Maintain comprehensive audit logs

---

### LLM07:2025 - System Prompt Leakage

**Description:** LLMs inadvertently revealing internal instructions, system prompts, or configuration details in responses.

**Why Added:** Community-requested addition following numerous real-world incidents where prompt leakage facilitated more sophisticated attacks.

**Impact:** Exposure of security controls, enabling targeted attacks, revealing business logic

**Example Attack Scenarios:**

- Attacker extracts system instructions through carefully crafted queries
- Revelation of internal data classification schemes
- Exposure of security control mechanisms

**Prevention:**

- Separate sensitive data from system prompts
- Avoid relying solely on system prompts for behavior control
- Implement guardrails outside the LLM
- Enforce security controls independently from the LLM
- Use prompt shields and filtering mechanisms
- Regularly test for prompt extraction vulnerabilities

---

### LLM08:2025 - Vector and Embedding Weaknesses

**Description:** Vulnerabilities in embedding-based systems, particularly RAG (Retrieval-Augmented Generation) architectures.

**Why Added:** RAG has become the default architecture for enterprise LLM applications, with 53% of companies using it. Community requested specific guidance on securing these systems.

**Common Vulnerabilities:**

- Unauthorized access to embedding stores
- Cross-user information leakage
- Injection attacks through retrieved content
- Poisoned embeddings affecting retrieval
- Insufficient access controls on vector databases

**Impact:** Data leakage, unauthorized access, poisoned retrievals, privacy violations

**Prevention:**

- Implement fine-grained access controls on vector stores
- Use permission-aware embedding systems
- Apply data validation and source authentication
- Maintain detailed audit logs
- Implement data review for classification
- Use separate embedding spaces for different security contexts

---

### LLM09:2025 - Misinformation

**Description:** LLMs generating false, misleading, or fabricated information (hallucinations) that is accepted without verification.

**Expanded Focus:** Now emphasizes the dangers of overreliance on LLM outputs without proper human oversight and validation.

**Impact:** Poor decision-making, security vulnerabilities, legal liabilities, reputational damage, safety risks

**Common Issues:**

- Hallucinated facts and statistics
- Fabricated citations and references
- Confidently incorrect information
- Biased or outdated information
- Fabricated code with security vulnerabilities

**Prevention:**

- Implement human oversight for critical decisions
- Cross-reference LLM outputs with authoritative sources
- Use confidence scores and uncertainty indicators
- Implement fact-checking mechanisms
- Apply domain-specific validation
- Maintain clear disclaimers about LLM limitations
- Use retrieval-augmented generation with verified sources

---

### LLM10:2025 - Unbounded Consumption

**Description:** Excessive or uncontrolled resource usage leading to service disruptions, financial exploitation, or unauthorized model replication.

**Evolution:** Previously "Model Denial of Service" - expanded to include broader resource management and cost concerns.

**Risk Types:**

- **Denial of Service (DoS):** Resource exhaustion attacks
- **Denial of Wallet (DoW):** Excessive operational costs in cloud environments
- **Resource Overload:** Computational resource overwhelming
- **Model Extraction:** Unauthorized model replication

**Impact:** Service disruptions, inflated costs, degraded performance, competitive disadvantage

**Example Attack Scenarios:**

- Attacker sends resource-intensive queries to exhaust compute
- Flood of API requests inflating operational costs
- Long-running queries consuming excessive GPU time
- Systematic querying to extract model behavior

**Prevention:**

- Implement rate limiting on API requests
- Set strict timeout limits for queries
- Apply resource quotas per user/session
- Monitor usage patterns for anomalies
- Implement cost alerts and caps
- Use input size limits
- Apply query complexity analysis

---

## Key Trends and Insights

### 1. Real-World Validation

The 2025 list reflects actual incidents and exploits observed in production environments, moving beyond theoretical risks.

### 2. Shift Toward Systematic Defenses

Greater emphasis on architectural security controls rather than isolated vulnerability fixes.

### 3. Agent Security

Recognition that autonomous AI agents represent a new frontier in security challenges.

### 4. Supply Chain Maturity

Supply chain attacks have evolved from theoretical concerns to demonstrated real-world exploits.

### 5. Data Sensitivity

Organizations are now acutely aware of the risks of exposing sensitive data through LLM interactions.

### 6. RAG Security

With RAG becoming the dominant architecture, specific security guidance for embedding-based systems is critical.

## Additional OWASP Resources

### Related Projects

- **OWASP AI Security and Privacy Guide** - Comprehensive guidance on AI system security
- **OWASP Application Security Verification Standard (ASVS)** - Standards applicable to LLM output handling
- **OWASP API Security Top 10** - Relevant for LLM API implementations

### Tools and Frameworks

- **LLM AI Cybersecurity & Governance Checklist** - For CISOs and compliance officers
- **Threat Modeling Resources** - LLM-specific threat modeling guidance
- **Testing Tools:**
  - Garak - Probes LLMs for vulnerabilities
  - FuzzLLM - Fuzzer for generating malformed inputs
  - ARMORY - Platform for red teaming AI systems
  - Burp Suite LLM Plugins - API vulnerability scanning

### Community Engagement

- **Slack Channel:** #project-top10-for-llm on OWASP Slack
- **Bi-weekly Meetings:** Community sync sessions
- **GitHub:** Active development and issue tracking
- **LinkedIn:** Updates and announcements

## License

The OWASP Top 10 for LLM Applications is licensed under Creative Commons CC BY-SA 4.0, making it freely available for use and adaptation.

## Conclusion

The OWASP Top 10 for LLM Applications represents the collective wisdom of hundreds of security professionals addressing one of the fastest-moving spaces in cybersecurity history. As LLM technology continues to evolve, so too will the threat landscape. Organizations must remain vigilant, adapt their security practices, and expect the unexpected as new vulnerabilities emerge.

The evolution from 2023 to 2025 demonstrates the rapid maturation of both LLM technology and the security community's understanding of its risks. What began as largely theoretical concerns have become concrete, exploited vulnerabilities requiring sophisticated defensive strategies.

---

_Last Updated: December 2024_
_Document Version: 2025_
_Source: OWASP Foundation - GenAI Security Project_
