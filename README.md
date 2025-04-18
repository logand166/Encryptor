# 🔒 Secure File Encryptor/Decryptor V2.0 🛡️ (Enhanced Edition)

| Section | Content |
|---------|---------|
| **🌟 Description** | An upgraded secure GUI tool with new security features and enhanced UX |
| **✨ New Features** | |
| 📊 Password Strength Meter | Real-time visual feedback on password complexity (color-coded) |
| 👁️‍🗨️ Password Visibility Toggle | Show/hide passwords during entry |
| 🗑️ Secure File Deletion | Optional permanent deletion of source files after processing |
| 📈 Improved Progress Tracking | Detailed logging and accurate progress bars |
| **🔐 Enhanced Security** | |
| 🛡️ Unique Nonce per Chunk | Fixed vulnerability of nonce reuse in chunked encryption |
| 🧩 Chunk Sequence Validation | Additional data binding prevents chunk tampering |
| 🧹 Secure Temp Cleanup | Better error handling and file cleanup |
| **📋 Updated Usage Guide** | |
| 🔒 Encryption | 1. Select file<br>2. Set password (watch strength meter)<br>3. Choose output path<br>4. Toggle options:<br>   - 👁️ Show password<br>   - 🗑️ Delete original<br>5. Start encryption |
| 🔓 Decryption | 1. Select encrypted file<br>2. Enter password<br>3. Auto-generated output name (.decrypted)<br>4. Start decryption |
| **⚙️ Technical Upgrades** | |
| 🔄 Chunk Processing | Now uses:<br>- Unique nonce per chunk<br>- Additional data binding<br>- Better memory management |
| 🛠️ Code Structure | Improved error handling and thread safety |
| **📜 License** | MIT License - Free for everyone |
| **⬇️ Installation** | `pip install PyQt5 cryptography qt_material` |
| **📸 UI Preview** | ![Enhanced UI](https://github.com/logand166/Encryptor/blob/main/Screenshot2.jpg) |

## 🆚 Feature Comparison

| Feature | Original | Enhanced |
|---------|----------|----------|
| Password Feedback | ❌ None | ✅ Strength meter + colors |
| Security Level | ⚠️ Chunk vulnerability | 🔐 Fixed nonce reuse |
| File Management | Basic cleanup | 🧹 Secure temp deletion |
| UX | Standard | 👁️‍🗨️ Toggleable passwords |

## 🚀 Why Upgrade?
- Military-grade security fixes
- Professional UX improvements
- Transparent operation logging
- Safer file handling

> 💡 Pro Tip: Always verify file integrity after decryption!
