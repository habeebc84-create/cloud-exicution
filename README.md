# CloudGuard AI Threat Detection

A portable front-end prototype for a cloud-based machine-learning threat detection capstone. It demonstrates the project workflow: data collection, preprocessing, ML classification, real-time alerting, and reporting.

## Run with Docker

```bash
docker build -t cloudguard-ai .
docker run --rm -p 8080:80 cloudguard-ai
```

Then open `http://localhost:8080` in a browser.

## Prototype features

- Security overview dashboard and threat activity chart
- Simulated live event stream and ML scan results
- Log-file selection simulation (`.csv`, `.json`, `.log`, `.txt`)
- Alert filtering and incident resolution
- Downloadable JSON report

This is a front-end demonstration using mock data. It does not connect to a production ML model or process actual security logs.
