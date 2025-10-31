# 🔐 Secure Client–Server Communication using XOR Encryption  
**Languages:** C & Python  
**Concepts:** Socket Programming • Encryption/Decryption • Multi-threaded Server • TCP Communication  

---

## 📘 Overview  
This project demonstrates a **secure client-server communication system** implemented in both **C** and **Python**, using a **custom XOR cipher** for encrypting and decrypting messages.  
It ensures **bi-directional**, **multi-client communication** over TCP sockets with proper encryption, decryption, and acknowledgment handling.

---

## 🧩 Features  
- 🔁 **Bi-directional communication** between client and server  
- 🔒 **XOR encryption/decryption** for secure message transfer  
- 🧵 **Multi-threaded server** in C (handles multiple clients concurrently)  
- 🌐 **TCP sockets** for reliable transmission  
- 💡 **Cross-language compatibility** (C ↔ Python)  
- 🪶 Lightweight, simple, and well-documented code  

---

## 🧠 System Architecture  

```mermaid
flowchart LR
    subgraph Clients
    A1[C Client] --> B1[Encrypt using XOR Cipher]
    A2[Python Client] --> B2[Encrypt using XOR Cipher]
    end

    B1 --> C1[XOR Logic]
    B2 --> C2[XOR Logic]

    C1 --> D[(TCP Socket Communication)]
    C2 --> D

    D --> E[Multi-threaded TCP Server]
    E --> F[Decrypt using XOR Cipher]
    F --> G[Encrypt ACK with XOR Cipher]
    G --> D
    D --> B1
    D --> B2
