<div align="center">
  <h1>🔐 Linux Privilege Escalation Enumeration Tool</h1>
  
</div>

<div align="center">

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Security](https://img.shields.io/badge/Security-FF6B6B?style=for-the-badge&logo=security&logoColor=white)

**Comprehensive Linux Privilege Escalation Scanner with Exploit Methods**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Output](#-output) • [Vulnerabilities](#-vulnerabilities-detected)

</div>

---

## 📋 Deskripsi

**Linux Privilege Escalation Enumeration Tool** adalah script bash yang dirancang untuk melakukan enumerasi menyeluruh terhadap sistem Linux guna menemukan celah privilege escalation. Tool ini tidak hanya mendeteksi vulnerability, tetapi juga menyediakan metode exploit dan contoh perintah yang dapat langsung digunakan.

Tool ini sangat berguna untuk:

- 🎯 **Penetration Testing** - Identifikasi celah keamanan dalam sistem
- 🔍 **Security Auditing** - Audit keamanan sistem Linux
- 📚 **Learning** - Belajar tentang berbagai teknik privilege escalation
- 🛡️ **Defensive Security** - Memahami celah yang perlu ditutup

---

## ✨ Features

### 🎨 **Enhanced User Interface**

- ASCII art banner yang menarik
- Progress bar untuk setiap tahap scanning
- Color-coded output (Critical, Warning, Info, Success)
- Box drawing untuk section headers
- Real-time progress tracking

### 🔎 **Comprehensive Vulnerability Detection**

- **25+ Kategori Pemeriksaan** mencakup berbagai vektor privilege escalation
- Deteksi otomatis untuk vulnerability yang diketahui
- Pemeriksaan mendalam untuk konfigurasi yang salah

### 💣 **Exploit Methods & Examples**

- Penjelasan metode exploit untuk setiap vulnerability
- Contoh perintah yang siap digunakan
- Referensi CVE dan link exploit
- Tips dan trik untuk setiap teknik

### 📊 **Dual Output Files**

- **Enumeration Report** - Laporan lengkap hasil scanning
- **Exploit Methods** - File terpisah berisi metode exploit dan contoh

---

## 🚀 Installation

### **Metode 1: Clone Repository**

```bash
git clone https://github.com/MadExploits/linemadpeas.git
cd linemadpeas
chmod +x madpeas.sh
```

### **Metode 2: Download Manual**

```bash
wget https://raw.githubusercontent.com/MadExploits/linemadpeas/refs/heads/main/madpeas.sh
chmod +x madpeas.sh
```

### **Persyaratan**

- Sistem operasi: Linux (semua distribusi)
- Shell: Bash 4.0+
- Permissions: User biasa (tidak perlu root)
- Tools opsional: `getcap`, `docker`, `systemctl` (untuk beberapa checks)

---

## 📖 Usage

### **Basic Usage**

```bash
./madpeas.sh
```

### **Dengan Output Custom**

```bash
# Script akan otomatis membuat file output dengan timestamp
# Format: privilege_escalation_report_YYYYMMDD_HHMMSS.txt
# Format: exploit_methods_YYYYMMDD_HHMMSS.txt
```

### **Menggunakan di Remote System**

```bash
# Upload script ke target
scp madpeas.sh user@target:/tmp/

# SSH ke target dan jalankan
ssh user@target
cd /tmp
chmod +x madpeas.sh
./madpeas.sh

# Download hasil
scp user@target:/tmp/privilege_escalation_report_*.txt ./
scp user@target:/tmp/exploit_methods_*.txt ./
```

### **Menggunakan dengan Curl (One-liner)**

```bash
curl -sSL https://raw.githubusercontent.com/MadExploits/linemadpeas/refs/heads/main/madpeas.sh | bash
```

---

## 📁 Output

Tool ini menghasilkan **2 file output**:

### 1. **Enumeration Report**

`privilege_escalation_report_YYYYMMDD_HHMMSS.txt`

- Laporan lengkap hasil scanning
- Informasi sistem
- Semua vulnerability yang ditemukan
- Konfigurasi sistem
- Network information
- Dan banyak lagi

### 2. **Exploit Methods**

`exploit_methods_YYYYMMDD_HHMMSS.txt`

- Metode exploit untuk setiap vulnerability
- Contoh perintah yang siap digunakan
- Referensi CVE
- Link ke exploit code
- Tips dan trik

---

## 🎯 Vulnerabilities Detected

Tool ini mendeteksi berbagai jenis vulnerability privilege escalation:

### **1. SUID/SGID Binaries**

- Deteksi binary dengan SUID/SGID bit
- Identifikasi binary yang berpotensi dieksploitasi
- Exploit methods untuk: find, python, vim, nmap, bash, dll

### **2. Sudo Misconfigurations**

- Sudo permissions tanpa password (NOPASSWD)
- Dangerous sudo commands (vim, python, find, dll)
- CVE-2019-14287 (Sudo bypass)
- CVE-2021-3156 (Baron Samedit)

### **3. World-Writable Files & Directories**

- File dan direktori yang writable oleh semua user
- PATH hijacking opportunities
- Writable scripts dan service files

### **4. Cron Jobs**

- System-wide cron jobs
- User cron jobs
- Writable cron files
- Wildcard exploitation

### **5. Linux Capabilities**

- Files dengan dangerous capabilities
- cap_setuid, cap_dac_override, dll

### **6. Environment Variables**

- PATH manipulation
- LD_PRELOAD hijacking
- LD_LIBRARY_PATH issues

### **7. Writable System Files**

- `/etc/passwd` writable
- `/etc/shadow` writable
- `/etc/sudoers` writable
- `/etc/sudoers.d` writable

### **8. Docker & Containers**

- Docker group membership
- Container escape opportunities
- Privileged containers

### **9. Kernel Exploits**

- **Dirty COW** (CVE-2016-5195)
- **DirtyPipe** (CVE-2022-0847) ⭐ NEW
- Kernel version analysis
- Exploit research recommendations

### **10. NFS Shares**

- NFS exports dengan `no_root_squash`
- Mounted NFS shares

### **11. Systemd Services & Timers**

- Writable systemd service files
- User systemd services
- Systemd timers

### **12. Password Files**

- Readable `/etc/shadow`
- Backup password files
- Users dengan UID 0

### **13. SSH Keys**

- Private SSH keys
- Authorized keys
- SSH configuration

### **14. History Files**

- Bash history
- Python history
- MySQL history
- Potential credentials

### **15. Additional Checks**

- Polkit/pkexec (PwnKit - CVE-2021-4034)
- Screen/Tmux sessions
- LXD/LXC containers
- Init scripts
- Mounted filesystems

---

## 🔥 DirtyPipe Detection (CVE-2022-0847)

Tool ini sekarang mendeteksi **DirtyPipe vulnerability** yang mempengaruhi:

- Linux kernel 5.8 hingga 5.16.11
- Linux kernel 5.10.102
- Linux kernel 5.15.25
- Linux kernel 5.17

Ketika terdeteksi, tool akan menampilkan:

- ⚠️ Critical warning
- 📝 Penjelasan vulnerability
- 💻 Contoh exploit commands
- 🔗 Link ke exploit repositories

---

## 📸 Screenshots

### Banner & Progress

```
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██╗     ██╗███╗   ██╗██████╗ ███████╗ █████╗ ███████╗              ║
║   ██║     ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝              ║
║   ██║     ██║██╔██╗ ██║██████╔╝█████╗  ███████║███████╗              ║
║   ██║     ██║██║╚██╗██║██╔═══╝ ██╔══╝  ██╔══██║╚════██║              ║
║   ███████╗██║██║ ╚████║██║     ███████╗██║  ██║███████║              ║
║   ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝              ║
║                                                                      ║
║   Privilege Escalation Enumeration & Exploitation Tool               ║
║   Comprehensive Vulnerability Scanner with Exploit Methods           ║
║   Powered by: https://github.com/MadExploits                         ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

[████████████████████████████████████████████████░░] 92% - Checking: Final Summary
```

### Output Example

```
[!!!] CRITICAL: Potential DirtyPipe vulnerability (CVE-2022-0847) detected!

┌──────────────────────────────────────────────────────────────────────┐
│ EXPLOIT METHOD: DirtyPipe (CVE-2022-0847)
├──────────────────────────────────────────────────────────────────────┤
Method: Uninitialized variable in pipe implementation allows...
Example: git clone https://github.com/Arinerron/CVE-2022-0847...
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Troubleshooting

### **Permission Denied**

```bash
chmod +x madpeas.sh
```

### **Script Tidak Dapat Menjalankan Beberapa Checks**

- Beberapa checks memerlukan tools tertentu (getcap, docker, dll)
- Tool akan otomatis skip checks jika tool tidak tersedia
- Ini normal dan tidak mempengaruhi checks lainnya

### **Output File Tidak Terbentuk**

- Pastikan direktori writable
- Check disk space
- Pastikan tidak ada permission issues

---

## ⚠️ Disclaimer

Tool ini dibuat untuk tujuan **edukasi dan security testing yang legal** saja. Pengguna bertanggung jawab penuh atas penggunaan tool ini. Penulis tidak bertanggung jawab atas penyalahgunaan tool ini untuk aktivitas ilegal.

**Gunakan hanya pada:**

- ✅ Sistem yang Anda miliki
- ✅ Sistem dengan izin tertulis
- ✅ Environment testing/development
- ✅ Penetration testing yang authorized

**JANGAN gunakan untuk:**

- ❌ Mengakses sistem tanpa izin
- ❌ Aktivitas ilegal
- ❌ Merusak sistem orang lain

---

## 🤝 Contributing

Kontribusi sangat diterima! Silakan:

1. Fork repository
2. Buat feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit perubahan (`git commit -m 'Add some AmazingFeature'`)
4. Push ke branch (`git push origin feature/AmazingFeature`)
5. Buat Pull Request

---

## 📚 References & Resources

- [GTFOBins](https://gtfobins.github.io) - Bypass techniques
- [Exploit-DB](https://www.exploit-db.com) - Exploit database
- [Linux Kernel Exploits](https://github.com/SecWiki/linux-kernel-exploits)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng) - Inspiration
- [HackTricks](https://book.hacktricks.xyz) - Privilege escalation guide

---

## 📝 Changelog

### Version 1.2.0

- ✨ Added DirtyPipe (CVE-2022-0847) detection
- 🎨 Enhanced UI with better formatting
- 📚 Added comprehensive README

### Version 1.1.0

- ✨ Added exploit methods for all vulnerabilities
- 🎨 Improved UI with progress bar
- 📊 Dual output files (report + exploit methods)

### Version 1.0.0

- 🎉 Initial release
- ✅ 25+ vulnerability checks
- 📝 Basic reporting

---

## 👤 Author

**MadExploits**

- GitHub: [@MadExploits](https://github.com/MadExploits)
- Repository: [linemadpeas](https://github.com/MadExploits/linemadpeas)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⭐ Star History

Jika tool ini membantu Anda, pertimbangkan untuk memberikan ⭐ pada repository ini!

---

<div align="center">

**Made with ❤️ for the Security Community**

[⬆ Back to Top](#-linux-privilege-escalation-enumeration-tool)

</div>
