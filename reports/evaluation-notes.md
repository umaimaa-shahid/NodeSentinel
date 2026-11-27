
# NodeSentinel — Evaluation Notes

## 1. Evaluation Objective

The objective of this evaluation is to assess the ability of NodeSentinel to identify selected security misconfigurations in Node.js/Express applications.

The evaluation will compare the scanner's findings against two application configurations:

- Vulnerable application
- Hardened application

The evaluation focuses on HTTP security headers, CORS configuration, cookie security attributes, and brute-force exposure.

## 2. Evaluation Environment

| Component              | Configuration                 |
| ---------------------- | ----------------------------- |
| Scanner                | NodeSentinel                  |
| Scanner language       | Python                        |
| Target framework       | Node.js / Express             |
| Vulnerable application | Pending                       |
| Hardened application   | Pending                       |
| Database               | Pending confirmation          |
| Testing environment    | Local development environment |

## 3. Evaluation Methodology

Each security module will be tested against both application configurations.

For every test:

1. Start the relevant application.
2. Run NodeSentinel against its local target URL.
3. Record the scanner output.
4. Compare the actual findings with the expected findings.
5. Identify missed detections and false positives.
6. Record any limitations affecting the result.

Only controlled tests against the team's own demo applications will be performed.

## 4. Evaluation Metrics

**Detection success:** Whether the scanner identifies the intended security issue.

**False positive:** A security issue reported when the tested configuration does not contain that issue.

**False negative:** An expected security issue that the scanner fails to identify.

**Detection coverage:** The number of intended test conditions successfully detected divided by the number of executed positive test conditions.

**Execution status:** Whether a test is pending, passed, failed, or blocked.

## 5. Planned Test Cases

| ID       | Module           | Application | Expected outcome                          | Status  |
| -------- | ---------------- | ----------- | ----------------------------------------- | ------- |
| EVAL-001 | Security Headers | Vulnerable  | Missing headers identified                | Not run |
| EVAL-002 | Security Headers | Hardened    | Configured headers accepted               | Not run |
| EVAL-003 | CORS             | Vulnerable  | Unsafe CORS identified                    | Not run |
| EVAL-004 | CORS             | Hardened    | Restricted CORS accepted                  | Not run |
| EVAL-005 | Cookie Security  | Vulnerable  | Missing cookie attributes identified      | Not run |
| EVAL-006 | Cookie Security  | Hardened    | Correct cookie attributes accepted        | Not run |
| EVAL-007 | Brute Force      | Vulnerable  | Lack of observable rate limiting reported | Not run |
| EVAL-008 | Brute Force      | Hardened    | Rate-limiting behavior observed           | Not run |

## 6. Current Evaluation Status

The evaluation design and test cases have been prepared.

Execution is pending completion and availability of the vulnerable and hardened Express applications.

No detection rates, false-positive rates, or successful experimental results are claimed at this stage.

## 7. Known Evaluation Limitations

- Security checks depend on the HTTP responses and endpoints accessible to the scanner.
- Cookie evaluation requires actual Set-Cookie responses.
- HSTS evaluation requires HTTPS.
- A limited number of login attempts cannot conclusively prove the absence of rate limiting.
- A rate-limit response does not establish protection against every brute-force strategy.
- Automated configuration checks do not replace manual security testing.
- Results will be limited to the specific demo applications and test conditions used.
