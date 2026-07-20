# Security Writeups

A collection of my security writeups, lab solutions, and vulnerability report samples.

This repository documents my journey in offensive security through hands-on labs, primarily focused on web application security. Every lab is solved manually, documented in detail, and accompanied by a professional-style security report.

## Objectives

* Develop practical offensive security skills
* Practice vulnerability analysis and exploitation
* Improve technical documentation and reporting
* Build a public security portfolio

## Repository Structure

Each lab is organized using the following structure:

```text
lab-name/
├── images/
├── writeup.md
└── report.md
```

### writeup.md

A detailed walkthrough of the discovery and exploitation process, including:

* Lab Information
* Summary
* Reconnaissance
* Exploitation
* Result

### report.md

A professional vulnerability report written in a bug bounty style, including:

* Executive Summary
* Vulnerability Details
* Proof of Concept
* Impact
* Remediation
* References

## Covered Topics

* SQL Injection
* Cross-Site Scripting (XSS)
* Authentication
* Access Control
* Business Logic Vulnerabilities
* Server-Side Request Forgery (SSRF)
* File Upload Vulnerabilities
* OAuth
* XML External Entity (XXE)

## Labs

### SQL Injection

* Blind SQL Injection with Conditional Responses
* SQL Injection with Filter Bypass
* SQL Injection UNION Attack

### Cross-Site Scripting (XSS)

* DOM-based XSS
* Stored XSS with CSP Bypass
* XSS via JavaScript Template Literals (DOM)

### Authentication

* 2FA Bypass
* Password Reset Poisoning
* Brute Force with IP Bypass

### Access Control

* IDOR on Sensitive Data
* Privilege Escalation via Parameter Manipulation
* Multi-step Access Control Bypass

### Business Logic

* Price Manipulation
* Workflow Bypass
* Excessive Trust in Client-side Controls
* Inconsistent Security Controls
* Authentication Bypass via Flawed State Machine

### SSRF

* SSRF with Filter Bypass
* Blind SSRF with Out-of-Band Detection

### File Upload

* Web Shell via Extension Bypass
* Remote Code Execution via Polyglot File Upload

### OAuth

* OAuth Account Hijacking via `redirect_uri`
* Stealing OAuth Tokens via Open Redirect

### XXE

* Blind XXE with Out-of-Band Interaction

## Disclaimer

All writeups are based on intentionally vulnerable lab environments such as PortSwigger Web Security Academy. They are published for educational and research purposes only and do not target real-world systems.

---

**Author:** Soroush Maleki (abysseraphim)
