# AI intrusion detection: live demo

- **[Live IDS console](https://shakthihs07-shs.github.io/ids-demo/live/)**: network flows scored in real time, in your browser, by a hybrid
  detector (Gradient Boosting for known attacks, Isolation Forest for attack types it never saw), with an
  analyst review queue.
- **[Live attack tracker](https://152-70-6-78.sslip.io/)**: real attacks on an internet-facing honeypot
  (OpenCanary on Oracle Cloud) as they happen: login attempts, scans and exploit payloads, mapped to
  MITRE ATT&CK, with IP addresses truncated and passwords never stored.
- **[Results dashboard](https://shakthihs07-shs.github.io/ids-demo/)**: model comparison on NSL-KDD and CIC-IDS2017, novel-attack detection,
  MITRE ATT&CK coverage, alert-threshold trade-off, drift, and an ISO/IEC 27001:2022 risk register.

The detector runs client-side as ONNX models in onnxruntime-web. This repository holds only the published
pages and the data they read; the source code, research and risk assessment are in a private repository,
available on request.

Data: CIC-IDS2017 (Sharafaldin, Habibi Lashkari and Ghorbani, ICISSP 2018), labels corrected by
Engelen, Rimmer and Joosen (KU Leuven, WTMC 2021) and Liu et al. (CNS 2022); NSL-KDD (Tavallaee et al.,
CISDA 2009). `live/replay.csv.gz` is a sample of 17,353 CIC-IDS2017 test flows.

Author: Shakthi H S, MSc Cybersecurity (IU Berlin).
