# 🔐 Phishing Site Detector

A Python-based phishing URL detection tool that uses multiple real-time APIs to determine if a website is legitimate or potentially malicious. The application includes a GUI built with Tkinter and uses VirusTotal, IPQualityScore, WHOISXML, and Google Safe Browsing APIs.

---

## 🧠 Features

- 🔍 Checks for HTTPS usage
- 🔗 Detects redirects and shortened links
- 🌐 Integrates with:
  - ✅ VirusTotal API
  - ✅ IPQualityScore API
  - ✅ WHOISXML API
  - ✅ Google Safe Browsing API
- ⚠️ Identifies unsafe domains and URLs in real-time
- 🧾 Displays detailed threat information
- 🖥️ Simple GUI for easy use
- 🛠️ Executable (`.exe`) file available with custom icon

---

## 📦 Requirements

- Python 3.9 or above
- Modules:
  - `requests`
  - `tkinter`
  - `validators`
  - `colorama`

Install all dependencies with:
```bash
pip install -r requirements.txt



🚀 How to Run
🧪 From Source (Python)
bash
Copy code
python main.py
🧊 From Executable
Double-click the Phishing_Site_Detector.exe file (available in the dist/ folder).

🧪 Example URLs to Test
Type	Example URL
✅ Legit	https://www.google.com
✅ Legit	https://www.facebook.com
❌ Phishing	http://secure-appleid.apple.com-signin.in
❌ Phishing	http://bit.ly/2PhishLogin
❌ Phishing	http://tinyurl.com/fakeaccountverify
❌ Phishing	http://login-update-verification.com
❌ Phishing	http://accounts-security-check-appleid.com

🧰 Folder Structure
graphql
Copy code
Phishing Site Detector/
│
├── main.py                # Main app logic
├── gui.py                 # GUI code (merged if simplified)
├── apis/                  # API logic files (optional if merged)
├── icon.ico               # App icon
├── dist/                  # Contains the generated .exe
├── README.md              # Project description (this file)
└── requirements.txt       # Python dependencies
