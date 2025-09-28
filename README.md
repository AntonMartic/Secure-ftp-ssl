# Secure SSL/TLS File Transfer

An educational implementation of a secure file transfer system in Java using **SSL/TLS sockets**.  
This project was developed as part of a Networking and Communications university assignment to demonstrate secure client-server communication, encryption, and authentication.

---

## 🔎 Overview

This project implements a simplified, secure FTP-like application where authorized clients can:
- **Download** files from the server
- **Upload** files to the server
- **Delete** files on the server

All communication between the client and the server is performed over **SSL/TLS**, ensuring confidentiality, integrity, and authenticity.

The system demonstrates core security concepts:
- Encrypted data transmission  
- Data integrity protection  
- Mutual authentication between client and server  
- Separate keystores and truststores for each party  

> **Disclaimer:** This is an educational project, not intended for production use.

---

## 🔥 Features

- **SSL/TLS Encryption**: All file transfers are encrypted over a secure socket.
- **Data Integrity**: Ensures that files are not altered during transit.
- **Mutual Authentication**: Both client and server authenticate each other using certificates.
- **Separate Keystores/Truststores**: Client and server maintain their own credentials.
- **File Operations**: Download, upload, and delete text files securely.

---

## 🔐 Security Concepts Implemented

1. **Data Integrity** – Achieved through SSL/TLS, which provides message authentication codes (MACs).
2. **Encryption** – All file contents and commands are encrypted in transit.
3. **Strong Cryptography** – Configured to use robust cipher suites supported by Java.
4. **Distinct Keystores and Truststores** – Each side has its own key pair and trusted certificates.
5. **Server Authentication** – Client verifies the server certificate.
6. **Client Authentication** – Server verifies the client certificate.

---

## ⚙️ Installation & Usage

### Prerequisites
- Java Development Kit (JDK): Version 8 or higher.
- Java keytool utility (included with JDK) to generate keystores and truststores.
- A Java IDE (IntelliJ IDEA, Eclipse) or command-line terminal.

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/secure-ssl-tls-file-transfer.git
cd secure-ssl-tls-file-transfer
```

### 2. Generate Keystores and Truststores (if you want your own)

```bash
# Server keystore
keytool -genkeypair -alias serverkey -keyalg RSA -keysize 2048 -keystore serverkeystore.jks -validity 365

# Server truststore (import client cert)
keytool -import -file client.cer -alias clientcert -keystore servertruststore.jks

# Client keystore
keytool -genkeypair -alias clientkey -keyalg RSA -keysize 2048 -keystore clientkeystore.jks -validity 365

# Client truststore (import server cert)
keytool -import -file server.cer -alias servercert -keystore clienttruststore.jks
```

### 3. Compile and Run

Compile server and client:
```bash
javac Server.java Client.java
```

Start the server:
```bash
java Server
```

Start the client:
```bash
java Client
```

### 4. Perform File Operations

From the client side, you can issue commands such as:
```txt
download myfile.txt
upload report.txt
delete oldfile.txt
```

All interactions will occur securely over SSL/TLS.

## 📂 Project Structure

---

```txt
.
├── Client.java            # Client-side implementation
├── Server.java            # Server-side implementation
├── /keystores             # Example keystores and truststores (If you generate your own)
└── README.md
```
