# 🔐 Secure File Upload Portal

### A Python-Based Web Application for Secure File Upload and Validation

## 📌 Project Overview

The **Secure File Upload Portal** is a web-based application developed using Python and Flask. It provides a secure platform for uploading files by validating file types, checking file content, and identifying potentially suspicious PDF files.

The application also includes an Admin Dashboard to monitor uploaded files, view upload history, review security logs, and download accepted files.

## 🎯 Project Objectives

- Provide a secure file upload environment.
- Validate uploaded files using their actual content.
- Detect suspicious or potentially unsafe PDF files.
- Prevent unauthorized file access.
- Maintain upload history and security logs.
- Provide an administrative dashboard for monitoring activities.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web application framework |
| HTML5 | Web page structure |
| CSS3 | User interface design |
| SQLite | Database management |
| Pillow | Image validation |
| pypdf | PDF validation and inspection |
| Gunicorn | Production application server |

## ✨ Main Features

### 1. Secure File Upload
- Supports PDF, PNG, JPG and JPEG files.
- Maximum upload size of 5 MB.
- Validates file extensions and actual file content.
- Uses unique filenames for stored uploads.

### 2. File Validation
- Checks image formats using Pillow.
- Verifies PDF file signatures.
- Checks PDF readability and encryption.
- Inspects PDFs for suspicious active-content features.

### 3. Admin Dashboard
- Displays total uploaded files.
- Shows PDF and image statistics.
- Displays upload history.
- Provides security activity logs.
- Allows authorized administrators to download accepted files.

### 4. Security Features
- File type validation.
- File size restrictions.
- Secure filename handling.
- Private file storage.
- Session-based admin authentication.
- Protected file downloads.
- Security event logging.

## ⚙️ Project Structure

```text
Secure-File-Upload-Portal/
│
├── app.py
├── requirements.txt
├── .gitignore
├── uploads.db
│
├── templates/
│   ├── index.html
│   ├── admin.html
│   └── admin_login.html
│
└── README.md
```

*Note: The SQLite database and private upload storage are generated or maintained locally and should not be committed to GitHub.*

## 🚀 Installation and Setup

### Step 1: Clone the repository

```bash
git clone https://github.com/abhiharikrishna27/Secure-File-Upload-Portal.git
```

### Step 2: Open the project folder

```bash
cd Secure-File-Upload-Portal
```

### Step 3: Create a virtual environment

```bash
py -m venv venv
```

### Step 4: Activate the virtual environment (Windows PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
```

### Step 5: Install dependencies

```bash
pip install -r requirements.txt
```

### Step 6: Run the application

```bash
py app.py
```

### Step 7: Open in your browser

```text
http://127.0.0.1:5000
```

## 🔒 Security Note

This project implements file validation and suspicious PDF feature inspection. These checks do not replace a dedicated antivirus or malware scanning engine and cannot guarantee that every malicious file will be detected.

For production use, configure strong administrator credentials and a secure secret key through environment variables. Use persistent, protected storage and HTTPS.

## 🌐 Live Application

[Secure File Upload Portal – Live Website](https://secure-file-upload-portal-h67q.onrender.com)

## 📂 GitHub Repository

[View Source Code on GitHub](https://github.com/abhiharikrishna27/Secure-File-Upload-Portal)

## 🎓 Academic Project

**Project Title:** Secure File Upload Portal  
**Domain:** Cyber Security  
**Programming Language:** Python  
**Framework:** Flask  
**Project Type:** Web-Based Application

---

*Developed as part of a Cyber Security Internship Project.*