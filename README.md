# Brute Force Cyber Attack Detection Simulator

**Course:** SEN2211 Data Structures I / SEN2212 Data Structures II  
**Authors:** Glory Mturi Elias, Cem Suay Asıldoğan, Deniz Doga  
**Language:** Java (OpenJDK 21)  
**Year:** 2025

---

## Overview

A JavaFX desktop application that monitors failed login attempts per IP address and detects brute force attacks in real time. The system uses a **sliding window algorithm** to evaluate whether any IP has exceeded a configurable failure threshold within a rolling time period. When an IP crosses the threshold it is flagged and blocked; if no further attempts arrive it automatically reverts to CLEAN once the window expires.

The project demonstrates direct application of data structures studied in SEN2211 (linked lists and queues) and SEN2212 (hash-based structures) to a practical cybersecurity problem.

---

## Data Structures Used

Three data structures form the detection engine:

| Structure | Role | Complexity |
|---|---|---|
| `HashMap<String, LinkedList<Long>>` | Maps each IP address to its ordered timestamp history | O(1) avg lookup & insert |
| `LinkedList<Long>` (FIFO Queue) | Stores Unix timestamps of recent failed attempts per IP; head = oldest, tail = newest | O(1) head removal, O(1) tail insert |
| `HashSet<String>` | Tracks blocked IPs for fast membership testing | O(1) contains / add |

### Why HashMap over alternatives?

| Structure | Lookup | Insert | Used? |
|---|---|---|---|
| HashMap | O(1) avg | O(1) avg | Yes — primary map |
| TreeMap | O(log n) | O(log n) | No — too slow |
| Array/List | O(n) | O(1) | No — O(n) lookup |
| LinkedList (Queue) | O(1) head/tail | O(1) | Yes — per-IP queue |

---

## Algorithm — Sliding Window Detection

The core method `logAttemptForIP(String ip)` executes four steps on every incoming failed login attempt:

**Step 1 — HashMap Insert (O(1))**  
If the IP has not been seen before, a new empty `LinkedList` is created and associated with it via `putIfAbsent()`. This is idempotent.

**Step 2 — Timestamp Append (O(1))**  
The current system time (`System.currentTimeMillis()`) is appended to the tail of the `LinkedList` using `addLast()`.

**Step 3 — Window Expiry (amortised O(1))**  
A `while` loop inspects the head of the list. Any timestamp older than `TIME_WINDOW` milliseconds is removed via `removeFirst()`. Each timestamp is added once and removed at most once, giving amortised O(1) per call.

**Step 4 — Threshold Check (O(1))**  
The list's `size()` is compared against `THRESHOLD`. If count ≥ threshold, an alert is raised and the IP is added to the `blockedIPs` HashSet.

```java
loginAttempts.putIfAbsent(ip, new LinkedList<>());       // Step 1
LinkedList<Long> ts = loginAttempts.get(ip);
ts.addLast(System.currentTimeMillis());                  // Step 2
while (!ts.isEmpty() && now - ts.peekFirst() > TIME_WINDOW)
    ts.removeFirst();                                    // Step 3
if (ts.size() >= THRESHOLD) { /* trigger alert */ }      // Step 4
```

---

## Complexity Analysis

### Time Complexity

| Operation | Average Case | Worst Case | Notes |
|---|---|---|---|
| HashMap get / putIfAbsent | O(1) | O(n) | Worst case: hash collision chain |
| LinkedList addLast | O(1) | O(1) | Direct tail pointer |
| LinkedList peekFirst | O(1) | O(1) | Direct head pointer |
| LinkedList removeFirst | O(1) | O(1) | Direct head pointer |
| LinkedList size() | O(1) | O(1) | Internal counter maintained |
| Window expiry loop | O(k) per call | O(k) per call | Amortised O(1): each entry removed once |
| Full logAttempt() call | **O(1) amortised** | O(n+k) | n=IPs (collision), k=expired entries |

### Space Complexity

**O(I × T)** where:
- **I** = number of unique IP addresses currently tracked
- **T** = maximum timestamps stored per IP, bounded by THRESHOLD (default 5)

In practice both I and T are small, making the memory footprint negligible.

---

## Features

- **Live dashboard** — four stat cards: Total Attempts, Unique IPs, Alerts Fired, Blocked IPs
- **IP Watchlist table** — real-time table with colour-coded status badges per IP
- **Attempt Frequency bar chart** — rolling 12-slot bar chart updated on every attempt
- **Event log** — timestamped log of all events with severity levels (INFO / WARN / ALERT / BLOCKED)
- **Configurable parameters** — THRESHOLD (1–50) and TIME_WINDOW in seconds (1–120) via spinners; changes take effect immediately without restart
- **Simulate Attack button** — fires 6 rapid attempts at 400 ms intervals using a non-blocking JavaFX `Timeline` (replaces `Thread.sleep`)
- **Passive window expiry** — a 1-second background ticker calls `refreshTable()`, pruning expired timestamps so IPs revert to CLEAN even when no new attempts arrive
- **Reset button** — clears all state, counters, chart data, and the event log

---

## IP Status Escalation

Each IP progresses through four states based on its hit count within the current window:

| Status | Condition | Colour |
|---|---|---|
| CLEAN | 0–59% of threshold | Green |
| WATCHING | 60–99% of threshold | Amber |
| ATTACK | ≥ threshold (first detection) | Red |
| BLOCKED | Post-alert (all subsequent attempts) | Red |

---

## Default Configuration

| Parameter | Default | Range |
|---|---|---|
| THRESHOLD | 5 failed attempts | 1–50 |
| TIME_WINDOW | 10 seconds (10,000 ms) | 1–120 s |

---

## How to Run

**Requirements:** Java 21 (OpenJDK 21) with JavaFX on the classpath.

```bash
# If JavaFX is bundled with your JDK (e.g. Liberica Full JDK):
javac BruteForceDetector.java
java BruteForceDetector

# If using a separate JavaFX SDK:
javac --module-path /path/to/javafx/lib --add-modules javafx.controls,javafx.fxml BruteForceDetector.java
java  --module-path /path/to/javafx/lib --add-modules javafx.controls,javafx.fxml BruteForceDetector
```

---

## Testing

Six scenarios were validated, all producing expected output:

| Scenario | Input | Expected | Result |
|---|---|---|---|
| Normal usage | 1–2 attempts from multiple IPs | All CLEAN | PASS |
| Escalation | 6 attempts at 500 ms intervals (threshold=5, window=10s) | CLEAN→WATCHING→ATTACK→BLOCKED | PASS |
| Window expiry | Attack then silence for 10+ seconds | Status reverts to CLEAN | PASS |
| Mixed traffic | Attacker + legitimate user simultaneously | Only attacker blocked | PASS |
| Threshold change | Change threshold 5→10 mid-session | Alert delayed to 10th attempt | PASS |
| Rapid-fire burst | 12 attempts in under 2 seconds | Blocked after 5th, remaining logged as BLOCKED | PASS |

---

## Project Structure

```
BruteForceDetector.java   — single-file application (detection engine + JavaFX GUI)
BruteForce_Report.pdf     — full project report
README.md                 — this file
```

### Key Classes / Methods

| Symbol | Description |
|---|---|
| `BruteForceDetector` | Main JavaFX `Application` class |
| `IPEntry` | Observable data model for a single TableView row |
| `logAttemptForIP(String ip)` | Core sliding window detection method |
| `simulateAttack()` | Fires a scripted sequence of rapid attempts via JavaFX `Timeline` |
| `refreshTable()` | Rebuilds the watchlist table and prunes expired timestamps (called every second) |
| `resetAll()` | Clears all state and resets the UI |
| `buildCSS()` | Returns the inline CSS stylesheet injected into the scene |

---

## Future Extensions

- Persistent storage for cross-session detection history
- Adaptive thresholds based on baseline traffic
- CIDR subnet matching for distributed attacks
- Live packet capture integration via Pcap4J

---

## References

1. Cormen, T. H., Leiserson, C. E., Rivest, R. L., & Stein, C. (2009). *Introduction to Algorithms* (3rd ed.). MIT Press.
2. Liang, Y. D. (2014). *Introduction to Java Programming, Comprehensive Version* (10th ed.). Pearson.
3. Oracle Corporation. (2023). *Java SE 21 API Documentation: HashMap, LinkedList, HashSet.*
4. McGraw, G. (2006). *Software Security: Building Security In.* Addison-Wesley.
5. OWASP Foundation. (2023). *Testing for Brute Force (OTG-AUTHN-003).*
6. Goodrich, M. T., & Tamassia, R. (2015). *Data Structures and Algorithms in Java* (6th ed.). Wiley.
