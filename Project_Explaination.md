This project is a \*\*Network Anomaly Simulator and Intrusion Detection System (IDS)\*\* powered by Machine Learning. 



At its core, it demonstrates how a modern security system can identify a cyberattack not by looking for a "fingerprint" of a known virus, but by learning what "normal" behavior looks like and flagging anything that feels out of place.



\### 🏛️ The Architecture (The Triple-Threat)

The project is built as a micro-service environment using \*\*Docker\*\*, consisting of three main actors:



1\.  \*\*The Generator (The "Users \& Hackers"):\*\* 

&#x20;   It constantly sends two types of traffic to the webserver. 

&#x20;   \*   \*\*Normal:\*\* Regular HTTP requests (mocking a user browsing a site).

&#x20;   \*   \*\*Anomaly:\*\* High-speed "SYN scan" bursts (mimicking a hacker probing for open ports).

2\.  \*\*The Webserver (The "Target"):\*\* 

&#x20;   A standard Nginx server that acts as a decoy. It doesn't know it's being watched; it just fulfills the requests it receives.

3\.  \*\*The Detector (The "Brain"):\*\* 

&#x20;   This is the star of the project. It uses a \*\*Sidecar Pattern\*\* (hooked directly into the webserver's network) to silently "sniff" every single packet. 



\### 🧠 The Machine Learning Magic

Instead of a checklist of rules, the Detector uses an \*\*Isolation Forest\*\* model (via Scikit-Learn).

\*   \*\*Phase 1: Learning.\*\* For the first few minutes, the model watches the traffic and assumes it is "normal." It builds a mathematical map of typical request counts and port activity.

\*   \*\*Phase 2: Detection.\*\* Once trained, it scores every new 30-second window of traffic. If it sees a sudden spike in unique ports or a flood of packets from a new IP, it flags it as an \*\*Anomaly\*\*.



\### 📊 Real-Time Visibility

The system outputs its findings to a \*\*Live Dashboard\*\* (\[index.html](cci:7://file:///d:/Projects/4/network-anomaly-sim/public/index.html:0:0-0:0)). This is a dark-mode web interface that shows:

\*   \*\*Real-time stats:\*\* Total requests, unique ports, and source IPs.

\*   \*\*ML Confidence:\*\* A "Score" that shows how close the traffic is to the baseline.

\*   \*\*Detection Logs:\*\* A persistent history where normal traffic is blue and detected anomalies (like port scans) pulse in \*\*Alert Red\*\*.



\### 🛠️ The Tech Stack

\*   \*\*Python 3.11:\*\* The language for all backend logic.

\*   \*\*Scapy:\*\* A powerful packet-crafting tool used to "sniff" the network.

\*   \*\*Scikit-Learn:\*\* The engine behind the Isolation Forest ML model.

\*   \*\*Docker Compose:\*\* Orchestrates all services so they run in isolated, repeatable containers.

\*   \*\*Vanilla JS/CSS:\*\* Powers the high-performance, real-time dashboard.



\### 🎯 Why This Matters

In the real world, hackers are constantly changing their methods. Traditional firewalls often miss "zero-day" attacks because they don't have a rule for them yet. This project shows how \*\*Anomalous Behavior Detection\*\* can catch those attacks by noticing they "feel different" from a regular user's behavior.

