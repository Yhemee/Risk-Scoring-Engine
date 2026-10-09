# Risk-Based Access Decision Prototype (Proof of Concept)

Research prototype for *A Governance and Risk-Based Approach to IAM in Hybrid Cloud Environments*.
Synthetic data only. Not production-ready.

## Files
- `risk_engine.py`: scoring logic (no dependencies)
- `test_risk_engine.py`: 30 test cases across 5 risk profiles
- `app.py`: Flask API, SQLite audit log, PyOTP step-up MFA
- `Dockerfile`, `requirements.txt`: isolated test environment

## Run
```
python test_risk_engine.py          # unit tests, no install needed
pip install -r requirements.txt
python app.py                       # API on :5000
docker build -t iam-poc . && docker run -p 5000:5000 iam-poc
```

## Scoring
| Factor | Points |
|---|---|
| Role: standard / elevated / privileged | 0 / 15 / 25 |
| Device: compliant / unmanaged / non-compliant | 0 / 15 / 30 |
| Location: usual / new country / high-risk | 0 / 15 / 30 |
| Time: business / after hours / night | 0 / 10 / 15 |
| Failed logins: 0 / 1-2 / 3-4 / 5+ | 0 / 10 / 30 / 40 |

Score < 30 = PERMIT, 30-59 = STEP-UP MFA REQUIRED, 60+ = DENY.

Override rules:
- 5+ failed attempts: DENY (suspected brute force)
- Privileged role on a non-compliant device: DENY
- Privileged role from a high-risk location: DENY
- Privileged role is never PERMIT without MFA (minimum STEP-UP)

## Example request
```
curl -X POST localhost:5000/access -H "Content-Type: application/json" -d '{
 "user_id":"u1","user_role":"privileged","device_posture":"compliant",
 "location":"usual","access_time":"2026-10-06T10:00:00","failed_attempts":0}'
```
