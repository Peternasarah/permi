# Permi Security Scan Report

**Target:** `./test_project`  
**Exported:** 2026-04-27 17:16:08  
**Tool:** [Permi](https://github.com/Peternasarah/permi) — AI-Powered Vulnerability Scanner  

---

## AI Filter Summary

> **11% noise reduction** — 1 false positive(s) removed from 9 raw findings

| Metric | Value |
|--------|-------|
| Raw findings | 9 |
| Real issues | **8** |
| False positives removed | 1 (11%) |
| 🔴 High | 5 |
| 🟡 Medium | 3 |
| 🔵 Low | 0 |

## Findings (8)

### 1. 🔴 `SQL001` — SQL Injection — string concatenation

**Severity:** HIGH  
**File:** `C:\Users\dashe\Permi\test_project\app\auth.py`  
**Line:** 8  

```
cursor.execute("SELECT * FROM users WHERE name = " + username)
```

**Why this matters:** Raw string concatenation used to build a SQL query. An attacker can inject arbitrary SQL through user input.

**Recommended fix:**

```
Use parameterised queries: cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
```

**AI verdict:** REAL [90%]  
**AI reasoning:** Direct string concatenation with user input in SQL query is exploitable  

---

### 2. 🔴 `SEC001` — Hardcoded secret — generic password or key assignment

**Severity:** HIGH  
**File:** `C:\Users\dashe\Permi\test_project\app\auth.py`  
**Line:** 12  

```
db_password = "admin1234"
```

**Why this matters:** A variable named password, secret, api_key, or token is assigned a string literal. Hardcoded credentials are a critical exposure risk if the code is shared or pushed.

**Recommended fix:**

```
Move to environment variable: import os; password = os.environ.get("DB_PASSWORD")  and add the key to your .env file (never commit .env)
```

**AI verdict:** REAL [90%]  
**AI reasoning:** Hardcoded password in executable code poses a clear security risk.  

---

### 3. 🟡 `USSD001` — USSD — missing input validation on sessionId or phoneNumber

**Severity:** MEDIUM  
**File:** `C:\Users\dashe\Permi\test_project\app\ussd.py`  
**Line:** 6  

```
session_id = request.form["sessionId"]
```

**Why this matters:** A USSD handler accesses sessionId or phoneNumber from the request without any visible validation. Unvalidated USSD inputs can be manipulated to hijack sessions or spoof callers.

**Recommended fix:**

```
Validate USSD inputs before use: if not re.match(r"^[0-9+]+$", phone_number): abort(400)  Always whitelist expected formats for sessionId and phoneNumber.
```

**AI verdict:** REAL [80%]  
**AI reasoning:** Direct access to request.form without validation poses a security risk  

---

### 4. 🟡 `USSD001` — USSD — missing input validation on sessionId or phoneNumber

**Severity:** MEDIUM  
**File:** `C:\Users\dashe\Permi\test_project\app\ussd.py`  
**Line:** 7  

```
phone      = request.form["phoneNumber"]
```

**Why this matters:** A USSD handler accesses sessionId or phoneNumber from the request without any visible validation. Unvalidated USSD inputs can be manipulated to hijack sessions or spoof callers.

**Recommended fix:**

```
Validate USSD inputs before use: if not re.match(r"^[0-9+]+$", phone_number): abort(400)  Always whitelist expected formats for sessionId and phoneNumber.
```

**AI verdict:** REAL [85%]  
**AI reasoning:** User-controlled input reaches the vulnerable point without validation.  

---

### 5. 🔴 `INS003` — Insecure — use of eval() on external input

**Severity:** HIGH  
**File:** `C:\Users\dashe\Permi\test_project\app\ussd.py`  
**Line:** 11  

```
result = eval(user_input)   # arbitrary code execution
```

**Why this matters:** eval() is called with a variable argument. If the variable contains user-supplied data, this allows arbitrary code execution.

**Recommended fix:**

```
Replace eval() with a safe alternative. For maths: use ast.literal_eval() or the operator module. Never pass user input to eval().
```

**AI verdict:** REAL [90%]  
**AI reasoning:** eval() with user_input allows arbitrary code execution.  

---

### 6. 🔴 `INS002` — Insecure — SSL/TLS verification disabled

**Severity:** HIGH  
**File:** `C:\Users\dashe\Permi\test_project\app\views.py`  
**Line:** 6  

```
response = requests.get(url, verify=False)
```

**Why this matters:** verify=False is passed to a requests call. This disables certificate validation and exposes the app to man-in-the-middle attacks.

**Recommended fix:**

```
Remove verify=False. If you need a custom CA: requests.get(url, verify="/path/to/ca-bundle.crt")
```

**AI verdict:** REAL [90%]  
**AI reasoning:** Disabled SSL/TLS verification exposes app to MITM attacks  

---

### 7. 🔴 `XSS001` — XSS — innerHTML assignment

**Severity:** HIGH  
**File:** `C:\Users\dashe\Permi\test_project\app\views.py`  
**Line:** 11  

```
return f"<div id='output'></div><script>document.getElementById('output').innerHTML = {comment}</script>"
```

**Why this matters:** innerHTML is set dynamically. If any part of the value comes from user input, this is a direct XSS vector.

**Recommended fix:**

```
Sanitise before assigning: element.textContent = userInput  (use textContent not innerHTML, or sanitise with DOMPurify)
```

**AI verdict:** REAL [90%]  
**AI reasoning:** user-controlled input directly used in innerHTML creates XSS risk  

---

### 8. 🟡 `INS001` — Insecure — debug mode enabled in production

**Severity:** MEDIUM  
**File:** `C:\Users\dashe\Permi\test_project\app\views.py`  
**Line:** 13  

```
debug = True
```

**Why this matters:** debug=True is set, likely in a Flask or Django app. Debug mode exposes stack traces and an interactive console to anyone who triggers an error.

**Recommended fix:**

```
Set debug=False in production. Use environment variable: app.debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
```

**AI verdict:** REAL [90%]  
**AI reasoning:** Debug mode in production is insecure and exposes sensitive information.  

---

*Report generated by [Permi](https://pypi.org/project/permi/) — 
Built in Nigeria. For Nigeria. Then for the World.*
