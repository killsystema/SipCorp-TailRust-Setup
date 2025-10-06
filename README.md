# SipCorp Setup - Automated Configuration Script

## 🧩 Description
**SipCorp Setup** is an automated **PowerShell script** for installing and configuring **remote access and VPN tools** on Windows machines.  
It installs and sets up **Tailscale** (secure VPN) and **RustDesk** (open-source remote desktop tool), replacing older solutions like TightVNC.  
At the end of execution, it sends a notification with credentials — including **Tailscale IP**, **RustDesk ID**, and **password** — to **Telegram** or **Discord** channels.

**Current Version:** 4.13.0-PROD  
**Author:** SipCorp  
**Release Date:** October 06, 2025  

This script is ideal for **corporate remote setups**, ensuring **security** and **full automation**.

---

## 🚀 Features

✅ **Automatic Installation** – Downloads and installs the latest versions of Tailscale and RustDesk.  
✅ **Secure Configuration** – Uses encrypted authentication keys and generates random passwords for RustDesk.  
✅ **Silent Mode** – Runs quietly with only a final success/error popup.  
✅ **Notifications** – Sends results to Discord or Telegram (IP, ID, password).  
✅ **Automatic Cleanup** – Removes old installations and registry remnants.  
✅ **Detailed Logs** – All actions are saved in `%TEMP%\sipcorp_install.log`.  
✅ **Auto-Elevation** – Requests admin permissions automatically if needed.

---

## ⚙️ Requirements

- **Operating System:** Windows 10/11 (x64)  
- **PowerShell:** Version 5.1+  
- **Internet Connection:** Required for downloads and notifications  
- **Permissions:** Must be run as Administrator  
- **Credentials:** Configure Tailscale, Discord, and Telegram keys (see below)

---

## 🧰 Installation and Usage

### 1. Download the Project
```bash
git clone https://github.com/killsystema/SipCorp-TailRust-Setup.git
cd SipCorp-TailRust-Setup
```

### 2. Configure Credentials (Optional)
Edit the file **SipCorp-TailRust-Setup.ps1** and update the function `Initialize-CredentialFile` with:

- `TailscaleKey` – Tailscale authentication key  
- `DiscordWebhook` – Discord webhook URL  
- `TelegramBotToken` and `TelegramChatId` – Telegram bot token and chat ID  

> All credentials are automatically encrypted at runtime for security.

---

### 3. Run the Script

**For Testing (via PowerShell):**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
powershell -ExecutionPolicy Bypass -File .\SipCorp-TailRust-Setup.ps1
```

**For Production (compile to EXE using ps2exe):**
```powershell
Install-Module ps2exe -Force
Invoke-ps2exe .\SipCorp-TailRust-Setup.ps1 .\SipCorpSetup.exe -noConsole -requireAdmin -version "4.13.0"
```

Then run **SipCorpSetup.exe** (it will request UAC and execute silently).

---

### 🕑 Duration
Setup takes approximately **2–3 minutes**.  
At the end:
- Popup: *“Installation completed successfully!”*  
- Notification sent to **Discord/Telegram** with full details.

---

## 📨 Example of Sent Notification

```
CONFIGURATION COMPLETED SUCCESSFULLY
Computer: WIN-T30JPPUQ01R
Tailscale IP: 100.66.147.75
Date/Time: 2025-10-06 08:50

RustDesk CREDENTIALS:
ID: 123456789
Administrative: 0RgzEGv4

KEEP THIS INFORMATION SECURE
```

---

## 🔍 Post-Installation Validation

**Check Tailscale**
```cmd
tailscale ip
```

**Check RustDesk**
```powershell
& "$env:ProgramFiles\RustDesk\rustdesk.exe" --get-id
Get-ItemProperty -Path "HKLM:\SOFTWARE\RustDesk" -Name "password"
```

**Test Connection:** Use the ID and password in RustDesk on another computer.

---

## 🧱 Compilation to EXE (Production)

To build the final executable:
```powershell
Invoke-ps2exe .\SipCorp-TailRust-Setup.ps1 .\SipCorpSetup.exe -noConsole -iconFile .\word.ico -requireAdmin -version "4.13.0" -title "SipCorp Setup v4.13"
```

Distribute the `.exe` file without exposing source code.

---

## ❓ FAQ

**Why use RustDesk instead of TightVNC?**  
RustDesk is open-source, encrypted, and performs better across platforms.

**How secure are the credentials?**  
Passwords are random and encrypted; keys are transmitted over HTTPS.

**What if the script hangs?**  
Check `%TEMP%\sipcorp_install.log`. Common causes: antivirus or network issues.

**Can I customize notification channels?**  
Yes — modify the `Initialize-CredentialFile` function.

**ARM64 Windows support?**  
Partial. Update download URLs for ARM builds manually.

**How do I uninstall everything?**  
Uninstall via *Settings → Apps*, remove registry keys, or delete RustDesk service:
```cmd
sc delete RustDesk
```

---

## 🧩 Troubleshooting

- **Installation Hang:** Check log file in `%TEMP%\sipcorp_install.log`.  
- **Password Not Applied:**  
  ```powershell
  & "$env:ProgramFiles\RustDesk\rustdesk.exe" --password [YOUR_PASSWORD]
  ```
- **Notification Failure:** Test webhook manually (Postman).  
- **Permission Errors:** Always run as Administrator.

---

## 🤝 Contributions

Contributions are welcome!

1. Fork the project  
2. Create your branch (`git checkout -b feature/AmazingFeature`)  
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)  
4. Push (`git push origin feature/AmazingFeature`)  
5. Open a Pull Request

---

## 🪪 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 💡 Acknowledgments

- **Tailscale:** for a simple and secure VPN  
- **RustDesk:** for an open-source remote desktop  
- **xAI / Grok:** for assisting in development and debugging  

---

**Made with ❤️ by SipCorp**  
*Last update: 2025-10-06*
