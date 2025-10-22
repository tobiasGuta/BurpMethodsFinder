# BurpMethodsFinder - HTTP Method Tester (brief)

A small Burp Suite extension (Jython 2.7) that tests a target URL with multiple HTTP methods and shows results in a table with selectable, syntax‑highlighted request/response panes. Right‑click any result or the editor to send the request to Repeater.

# Features

- Tests common HTTP methods (GET, HEAD, POST, PUT, OPTIONS, PATCH, DELETE).

- Stores raw request/response bytes and displays them using Burp message editors (colored like Repeater).

- Table view with status, total/body sizes and timing.

- Right‑click context menu to send selected or editor request to Repeater (handles common sendToRepeater overloads).

- Load target URL from Burp proxy history.

# Requirements

- Burp Suite with Extender API

- Jython 2.7 configured in Burp Extender

# Usage

- Drop the script into Burp Extender (Jython standalone JAR configured), open the "Methods Tester" tab, enter or load a URL, click "Test Methods", then right‑click a row or the editor to send to Repeater.

# Support
If my tool helped you land a bug bounty, consider buying me a coffee ☕️ as a small thank-you! Everything I build is free, but a little support helps me keep improving and creating more cool stuff ❤️
---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>

---