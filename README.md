# HML-SAODV

**Hybrid Machine Learning-based Secure Ad-hoc On-demand Distance Vector (SAODV) Routing Protocol**  
Thesis Project: Detection and Prevention of Blackhole and Wormhole Attacks in MANET

---

## 📌 Overview

**HML-SAODV** is a modified version of the traditional AODV (Ad-hoc On-demand Distance Vector) routing protocol. It integrates a simple machine learning technique to enhance security in Mobile Ad-hoc Networks (MANETs) by detecting and preventing **blackhole** and **wormhole** attacks.

This approach is lightweight, predictive, and proactive—analyzing node behavior to filter out malicious activities based on sequence number patterns.

---

## ⚙️ How It Works

HML-SAODV introduces an intelligent validation mechanism for sequence numbers in route replies:

1. **Sequence Number Prediction**:  
   A lightweight ML model predicts the next expected sequence number based on:
   - The last known sequence number.
   - The time elapsed since the last update.

2. **Reply Validation**:
   - If the received sequence number is **significantly higher** than the predicted one, it is **dropped** (suspicious).
   - If it's **close** but slightly higher, a **test packet** is sent.

3. **Test Packet Analysis**:
   - If the sequence number remains consistent after the test request, the node is **trusted**.
   - If it changes **significantly**, the node is **flagged as malicious** and discarded.

---

## 🧪 How to Test

### 📌 Requirements
- A Linux system (Recommended: Ubuntu 12)
- NS-2.35 network simulator

### 🛠 Setup Steps

1. **Install NS-2.35** on your Linux machine.  
   You can find it here: [http://www.isi.edu/nsnam/ns/](http://www.isi.edu/nsnam/ns/)

2. **Replace Default AODV**:
   - Navigate to:  
     `ns-allinone-2.35/ns-2.35/`
   - Replace the default AODV source code with the HML-SAODV implementation files.

3. **Recompile NS-2**:
   ```bash
   make clean
   make
   sudo make install

