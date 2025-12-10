Daark_CORS — Advanced CORS Misconfiguration Scanner

Daark_CORS is a powerful, fast, and accurate security tool designed to detect CORS misconfigurations across web applications.
It performs manual & automated Origin injection, analyzes responses in-depth, and highlights dangerous behaviors such as:

Wildcard origins

Origin reflection

Credential-based CORS vulnerabilities

Missing preflight headers

Dangerous ACAO + ACAC combinations

And more…

Daark_CORS provides real-time colored output, making it easy for penetration testers to visually identify red‑flag headers and critical findings instantly.

🚀 Features

🔥 Automatic dynamic Origin spoofing

🎨 Colored output highlighting:

CORS headers in red

Critical findings in bright red

Warnings in yellow

Normal headers in cyan

🧠 Smart analysis engine detecting:

Wildcard * ACAO

Reflected origins

Credentials allowed

Preflight misconfigurations

🧵 Threaded scanning for multiple origins (optional)

🧩 Works with GET and OPTIONS (preflight) requests

⚡ Fast, lightweight, and accurate

📦 Installation

git clone https://github.com/YOUR_USERNAME/Daark_CORS.git

cd Daark_CORS

python3 Daark_CORS

🕹 Usage

Basic Scan
python3 Daark_CORS.py https://example.com

Specify a custom Origin
python3 Daark_CORS.py https://example.com --origin https://attacker.com

Run preflight checks (OPTIONS)
python3 Daark_CORS.py https://example.com --preflight

Scan with multiple payload origins
python3 Daark_CORS.py https://example.com --payloads origins.txt

Example Output

[Request] GET -> https://example.com
[Response Status] 200
[Response Headers]:
  Access-Control-Allow-Origin: https://attacker.com   (RED)
  Access-Control-Allow-Credentials: true              (RED)

[Analysis]:
CRITICAL - Credentials + Reflected Origin
[Severity] CRITICAL

🛡 How It Works

Sends GET and/or OPTIONS requests with controlled Origin header

Captures full response headers

Highlights CORS-related headers in red

Passes all headers to the analysis engine

Produces a detailed severity report:

INFO

LOW

HIGH

CRITICAL

Daark_CORS follows industry standards used in penetration testing and bug bounty programs.

⚠️ Legal Disclaimer

This tool is strictly for educational and authorized penetration testing only.
You must not use Daark_CORS against systems you do not own or do not have explicit permission to test.

Any misuse of this tool is your sole responsibility.
The authors are not liable for any damages or legal consequences
