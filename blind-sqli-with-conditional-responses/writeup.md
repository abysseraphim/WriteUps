# Lab: Blind SQL Injection with Conditional Responses

| Field | Details |
|-------|---------|
| **Provider** | PortSwigger |
| **Difficulty** | Practitioner |
| **Category** | SQL Injection |
| **Date** | 2026-07-20 |

---

## Summary

Boolean-based blind SQL injection with conditional responses is a lab in the PortSwigger Web Security Academy. As the description states, the cookie is the injection entry point (source), and the application uses it to send a query that retrieves items. Since there are no direct query results, this is a blind test scenario — different modes will be explained throughout this writeup.

By manipulating the cookie value, the "Welcome back" message either appears or disappears depending on whether the injected condition evaluates to true. I used this message as a boolean oracle.

SQL injection is a well-known vulnerability — but what not everyone knows is how to exploit it manually, without relying on tools like sqlmap or ghauri. In this writeup, I'll walk through the entire exploitation flow step by step.

---

## Reconnaissance

SQL injection occurs when user input (source) is directly processed and, specifically in SQLi, placed into a SQL query (sink) without proper sanitization. There are different detection methods for different scenarios.

In a boolean-based blind scenario, I can't see the actual data — only an observable side effect. Here's how I approached detection:

There are two tests to verify the vulnerability. The first test's response must be identical to the original (in this lab, the original response contains "Welcome back", so a working payload should produce the same result).

**First test payloads:**

```
cookie' AND 1=1--
cookie' AND '1'='1
cookie" AND "1"="1
```

If one of the payloads works, the boolean oracle ("Welcome back") will appear in the response:

![image](images/1-detectingBooleanBasedBlind.png)
![image2](images/2-detectingBooleanBasedBlind.png)

Response matched:

![image3](images/3-detectingBooleanBasedBlind.png)

**Second test — confirming the vulnerability:**

Simply change `1` to any other number to make the condition evaluate to false:

![image4](images/4-confirmingVulnerability.png)

If the response no longer contains "Welcome back" and differs from the original, the SQL injection vulnerability is confirmed.

---

## Exploitation

There are three main types of SQL injection:

1. Union-based injection
2. Boolean-based blind injection
3. Time-based blind injection

In this case, I'm dealing with boolean-based blind injection — meaning everything is a yes or no, true or false. The goal is to craft conditions and infer information from the application's response.

### Identifying the Database

My initial assumption was MySQL (my brain's default), so I went straight for a payload to find the database name length:

![image5](images/5-tryingMySQLPayload.png)

"Welcome back" wasn't present in the response. My second guess was PostgreSQL — since the first character of `version()` output in PostgreSQL is `'P'`, I tried this payload:

![image6](images/6-tryingPostgressqlPayload.png)

It matched. Database confirmed: **PostgreSQL**.

### Finding the Database Name Length

Out of habit, I went for the database name length next:

![image7](images/7-findingDBlength.png)
![image8](images/8-findingDBlength.png)

I then remembered this step is only necessary in MySQL, not PostgreSQL — so I moved on.

### Finding the First Table Name Length

The next step was finding the length of the first table name:

![image9](images/9-findingLengthOfFirstTable.png)
![image10](images/10-findingLengthOfFirstTablesName.png)

Why do I need the table name length? Because once I know it, I can iterate through each character position and brute-force the value one character at a time.

The length turned out to be **5** — spelling `users`.

### Finding the First Table Name

Even though the lab description gives this away, I chose to enumerate it manually:

> **Note:** Since I know the target field's length, I can try all possible characters at each position. I just need to change the start position in `SUBSTRING` and keep the length fixed at `1` to move character by character.

![image11](images/11-findingNameOfFirstTable.png)
![image12](images/12-findingNameOfFirstTable.png)
![image13](images/13-findingNameOfFirstTable.png)
![image14](images/14-findingNameOfFirstTable.png)

And so on...

Table name confirmed: **`users`**

### Finding the First Column Name

Same strategy — starting with the length:

![image15](images/15-findingLengthOfFirstColumnName.png)

Length: **8**. Then, character by character:

![image16](images/16-findingNameOfFirstColumn.png)
![image17](images/17-findingNameOfFirstColumn.png)

First column: **`username`**

### Finding the Second Column Name

To find the next column, I changed the `OFFSET` to `1` (similar to `LIMIT 1,1` in MySQL) and repeated the same process.

Length of the second column:

![image18](images/18-findingLengthOfSecondColumnName.png)

Length: **8**. Name of the second column:

![image19](images/19-findingNameOfSecondColumn.png)
![image20](images/20-findingNameOfSecondColumn.png)

Second column: **`password`**

> **Reminder:** The goal is always to keep the condition true — the presence of "Welcome back" confirms that I'm extracting the correct character at each position.

### Enumerating Usernames

Now that I knew the column names (`username` and `password`), I moved on to the actual data. First, I found the length of the first username:

![image21](images/21-findingLengthOfFirstMemberNameInUsername.png)
![image22](images/22-findingLengthOfFirstMemberNameInUsername.png)

Length: **13** — that's `administrator`.

Then, character by character:

![image23](images/23-findingNameOfFirstMemberInUsername.png)
![image24](images/24-findingNameOfFirstMemberInUsername.png)

Username confirmed: **`administrator`**

### Dumping the Password

As always, I started with the password length:

![image25](images/25-findingLengthOfAdministratorPassword.png)
![image26](images/26-findingLengthOfAdministratorPassword.png)

Length: **20** — too long to brute-force manually in Repeater. Two options here:

**Option 1: Burp Intruder**

Use Intruder to iterate over `SUBSTRING` positions and filter responses by length or content match:

![image27](images/27-tryingToDumpPasswordWithBurpIntruder.png)
![image28](images/28-tryingToDumpPasswordWithBurpIntruder.png)
![image29](images/29-tryingToDumpPasswordWithBurpIntruder.png)

**Option 2: Custom Script**

![image30](images/30-writingCustomScript.png)
![image31](images/31-passwordFound.png)

---

## Result

Password extracted successfully. Login confirmed.

![image32](images/32-loginPage.png)
![image33](images/33-Solved.png)

---

## Impact & Remediation

**Impact:** This vulnerability allows an unauthenticated attacker to extract any data from the database — including credentials, session tokens, and other sensitive records — through a purely inference-based attack with no direct query output required. In this lab, it led to full account takeover of the `administrator` user.

**Remediation:** The root cause is unsanitized user input being concatenated directly into SQL queries. The fix is to use **parameterized queries (prepared statements)** instead of string concatenation — this ensures user input is always treated as data, never as SQL syntax. Additionally, applying the principle of least privilege to database accounts and implementing a WAF as a defense-in-depth layer can further reduce the attack surface.