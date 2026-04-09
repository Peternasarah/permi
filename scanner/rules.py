# scanner/rules.py
# Vulnerability detection rules for Permi's static source scanner.
# Each rule has: id, name, pattern (regex), severity, description.
# Patterns are intentionally broad — the AI filter removes false positives.

import re

RULES = [

    # ── SQL INJECTION ─────────────────────────────────────────────────────────

    {
        "id": "SQL001",
        "name": "SQL Injection — string concatenation",
        "severity": "high",
        "description": (
            "Raw string concatenation used to build a SQL query. "
            "An attacker can inject arbitrary SQL through user input."
        ),
        "pattern": re.compile(
            r'(execute|query|cursor\.execute)\s*\(\s*["\'].*\+',
            re.IGNORECASE
        ),
    },
    {
        "id": "SQL002",
        "name": "SQL Injection — f-string or format() in query",
        "severity": "high",
        "description": (
            "An f-string or .format() call is used inside a SQL query. "
            "User-controlled variables embedded this way are injectable."
        ),
        "pattern": re.compile(
            r'(execute|query|cursor\.execute)\s*\(\s*f["\']',
            re.IGNORECASE
        ),
    },
    {
        "id": "SQL003",
        "name": "SQL Injection — % formatting in query",
        "severity": "high",
        "description": (
            "% string formatting is used to build a SQL query. "
            "This is a classic injection vector."
        ),
        "pattern": re.compile(
            r'(execute|query)\s*\(\s*["\'].*%\s*[(\w]',
            re.IGNORECASE
        ),
    },

    # ── CROSS-SITE SCRIPTING (XSS) ────────────────────────────────────────────

    {
        "id": "XSS001",
        "name": "XSS — innerHTML assignment",
        "severity": "high",
        "description": (
            "innerHTML is set dynamically. If any part of the value comes "
            "from user input, this is a direct XSS vector."
        ),
        "pattern": re.compile(r'\.innerHTML\s*=', re.IGNORECASE),
    },
    {
        "id": "XSS002",
        "name": "XSS — document.write with variable",
        "severity": "high",
        "description": (
            "document.write() is called with a variable. "
            "Writing user-controlled content to the page enables XSS."
        ),
        "pattern": re.compile(r'document\.write\s*\(\s*\w', re.IGNORECASE),
    },
    {
        "id": "XSS003",
        "name": "XSS — Flask/Jinja2 |safe filter",
        "severity": "medium",
        "description": (
            "The Jinja2 |safe filter disables auto-escaping. "
            "If the variable contains user input, this enables XSS."
        ),
        "pattern": re.compile(r'\|\s*safe', re.IGNORECASE),
    },

    # ── HARDCODED SECRETS ─────────────────────────────────────────────────────

    {
        "id": "SEC001",
        "name": "Hardcoded secret — generic password or key assignment",
        "severity": "high",
        "description": (
            "A variable named password, secret, api_key, or token is "
            "assigned a string literal. Hardcoded credentials are a "
            "critical exposure risk if the code is shared or pushed."
        ),
        "pattern": re.compile(
            r'(password|passwd|secret|api_key|apikey|token|auth_key)'
            r'\s*=\s*["\'][^"\']{4,}["\']',
            re.IGNORECASE
        ),
    },
    {
        "id": "SEC002",
        "name": "Hardcoded secret — AWS key pattern",
        "severity": "high",
        "description": (
            "A string matching the format of an AWS Access Key ID was found. "
            "Exposed AWS keys can lead to full account compromise."
        ),
        "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
    },
    {
        "id": "SEC003",
        "name": "Hardcoded secret — private key header",
        "severity": "high",
        "description": (
            "A PEM private key header was found in the source code. "
            "Private keys must never be committed to a repository."
        ),
        "pattern": re.compile(
            r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
        ),
    },
    {
        "id": "SEC004",
        "name": "Hardcoded secret — Paystack or Flutterwave secret key",
        "severity": "high",
        "description": (
            "A Paystack or Flutterwave secret key pattern was found. "
            "Exposed payment gateway keys allow fraudulent transactions."
        ),
        "pattern": re.compile(r'(sk_live_|sk_test_)[a-zA-Z0-9]{20,}'),
    },
    {
        "id": "SEC005",
        "name": "Hardcoded secret — .env file with sensitive assignment",
        "severity": "high",
        "description": (
            "A .env file contains what appears to be a sensitive key or "
            "password assignment. .env files should never be committed."
        ),
        "pattern": re.compile(
            r'^(SECRET|PASSWORD|API_KEY|PRIVATE_KEY|TOKEN|AUTH)\s*=\s*.+$',
            re.IGNORECASE | re.MULTILINE
        ),
    },

    # ── USSD / NIGERIAN-SPECIFIC ──────────────────────────────────────────────

    {
        "id": "USSD001",
        "name": "USSD — missing input validation on sessionId or phoneNumber",
        "severity": "medium",
        "description": (
            "A USSD handler accesses sessionId or phoneNumber from the "
            "request without any visible validation. Unvalidated USSD "
            "inputs can be manipulated to hijack sessions or spoof callers."
        ),
        "pattern": re.compile(
            r'request\.(get|form|json|args)\s*[\.\[]\s*'
            r'["\']?(sessionId|phoneNumber|serviceCode)["\']?',
            re.IGNORECASE
        ),
    },
    {
        "id": "USSD002",
        "name": "USSD — wildcard or open-ended serviceCode handling",
        "severity": "medium",
        "description": (
            "A USSD serviceCode is compared to a wildcard or catch-all "
            "value. This may allow unintended service codes to trigger "
            "application logic."
        ),
        "pattern": re.compile(
            r'serviceCode\s*[=!]=\s*["\'][*\?]["\']',
            re.IGNORECASE
        ),
    },

    # ── INSECURE PRACTICES ────────────────────────────────────────────────────

    {
        "id": "INS001",
        "name": "Insecure — debug mode enabled in production",
        "severity": "medium",
        "description": (
            "debug=True is set, likely in a Flask or Django app. "
            "Debug mode exposes stack traces and an interactive console "
            "to anyone who triggers an error."
        ),
        "pattern": re.compile(r'debug\s*=\s*True', re.IGNORECASE),
    },
    {
        "id": "INS002",
        "name": "Insecure — SSL/TLS verification disabled",
        "severity": "high",
        "description": (
            "verify=False is passed to a requests call. "
            "This disables certificate validation and exposes the app "
            "to man-in-the-middle attacks."
        ),
        "pattern": re.compile(
            r'requests\.\w+\(.*verify\s*=\s*False', re.IGNORECASE
        ),
    },
    {
        "id": "INS003",
        "name": "Insecure — use of eval() on external input",
        "severity": "high",
        "description": (
            "eval() is called with a variable argument. If the variable "
            "contains user-supplied data, this allows arbitrary code execution."
        ),
        "pattern": re.compile(r'eval\s*\(\s*\w', re.IGNORECASE),
    },
    {
        "id": "INS004",
        "name": "Insecure — use of exec() on external input",
        "severity": "high",
        "description": (
            "exec() is called with a variable argument — same risk as eval()."
        ),
        "pattern": re.compile(r'exec\s*\(\s*\w', re.IGNORECASE),
    },
    {
        "id": "INS005",
        "name": "Insecure — pickle.loads() on untrusted data",
        "severity": "high",
        "description": (
            "pickle.loads() deserializes data. If the data comes from "
            "an untrusted source, this allows arbitrary code execution."
        ),
        "pattern": re.compile(r'pickle\.loads\s*\(', re.IGNORECASE),
    },
    {
        "id": "INS006",
        "name": "Insecure — subprocess with shell=True",
        "severity": "high",
        "description": (
            "subprocess is called with shell=True. If any part of the "
            "command string contains user input, this allows command injection."
        ),
        "pattern": re.compile(
            r'subprocess\.(run|call|Popen|check_output)\s*\(.*shell\s*=\s*True',
            re.IGNORECASE
        ),
    },
    {
        "id": "INS007",
        "name": "Insecure — os.system() with variable",
        "severity": "high",
        "description": (
            "os.system() is called with a variable argument. "
            "If the variable contains user input, this enables command injection."
        ),
        "pattern": re.compile(r'os\.system\s*\(\s*\w', re.IGNORECASE),
    },
]

# ── FILE EXTENSIONS TO SCAN ───────────────────────────────────────────────────
# Expanded to cover all common project types including mobile, backend, config.

SCANNABLE_EXTENSIONS = {
    # Python
    ".py",
    # JavaScript / TypeScript
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    # Web
    ".html", ".htm", ".vue", ".svelte",
    # Backend languages
    ".php", ".java", ".rb", ".go", ".cs", ".cpp", ".c",
    # Mobile
    ".dart", ".kt", ".swift",
    # Config / secrets
    ".env", ".env.local", ".env.production", ".env.development",
    ".yml", ".yaml", ".toml",
    # Data / API
    ".json", ".graphql", ".gql",
    # Shell scripts
    ".sh", ".bash",
}

# ── DIRECTORIES TO SKIP ───────────────────────────────────────────────────────
# These folders are never scanned — they contain dependencies or build artifacts.

SKIP_DIRS = {
    # Dependency folders — never contain your code
    "node_modules",
    ".pub-cache",
    "Pods",

    # Virtual environments
    "venv", ".venv", "env", ".env",

    # Version control
    ".git", ".svn",

    # Python cache
    "__pycache__",

    # Framework build outputs — contain generated code, not source
    ".next", ".nuxt", ".output", ".dart_tool",
    ".gradle", ".idea", ".vscode",

    # Native mobile build folders
    "ios", "android",

    # Test coverage reports
    ".nyc_output", "coverage",
}
