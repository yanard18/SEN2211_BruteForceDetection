import java.util.*;

/**
 * Sliding window brute force detection engine.
 *
 * Data structures:
 *   HashMap<String, LinkedList<Long>> — maps each IP to its timestamp history (SEN2212)
 *   LinkedList<Long> as FIFO queue   — ordered timestamps, O(1) head/tail ops (SEN2211)
 *   HashSet<String>                  — blocked IPs, O(1) membership check
 * 
 */
public class DetectionEngine {

    static final int  THRESHOLD = 5;
    static final long WINDOW_MS = 40_000;

    // SEN2212: HashMap — O(1) avg lookup per incoming IP
    private final Map<String, LinkedList<Long>> attempts = new HashMap<>();

    // SEN2212: HashSet — O(1) blocked-IP membership test on every request
    private final Set<String> blocked = new HashSet<>();

    /**
     * Records one failed login attempt from the given IP.
     * Adds the current timestamp to the tail of that IP's LinkedList (SEN2211 queue),
     * prunes timestamps older than WINDOW_MS from the head, then blocks the IP
     * if the window count meets or exceeds THRESHOLD.
     */
    public synchronized void logAttempt(String ip) {
        long now = System.currentTimeMillis();

        attempts.putIfAbsent(ip, new LinkedList<>());
        LinkedList<Long> ts = attempts.get(ip);

        ts.addLast(now);

        while (!ts.isEmpty() && now - ts.peekFirst() > WINDOW_MS)
            ts.removeFirst();

        if (ts.size() >= THRESHOLD)
            blocked.add(ip);
    }

    /**
     * Returns true if the IP is currently blocked.
     * Prunes expired timestamps first — this is the auto-unblock mechanism.
     * If the window clears naturally, the IP is removed from the blocked set.
     */
    public synchronized boolean isBlocked(String ip) {
        long now = System.currentTimeMillis();
        LinkedList<Long> ts = attempts.get(ip);
        if (ts == null) return false;
        ts.removeIf(t -> now - t > WINDOW_MS);
        if (ts.size() < THRESHOLD)
            blocked.remove(ip);
        return blocked.contains(ip);
    }

    /**
     * Returns the current threat status for an IP: BLOCKED / WATCHING / CLEAN.
     */
    public synchronized String getStatus(String ip) {
        if (isBlocked(ip)) return "BLOCKED";
        LinkedList<Long> ts = attempts.getOrDefault(ip, new LinkedList<>());
        int count = ts.size();
        return count >= (int) Math.ceil(THRESHOLD * 0.6) ? "WATCHING" : "CLEAN";
    }

    /**
     * Returns all tracked IPs as a JSON array for the /status endpoint.
     * Prunes each IP's window before serialising so the snapshot is current.
     */
    public synchronized String toJson() {
        long now = System.currentTimeMillis();
        StringBuilder ips = new StringBuilder("[");
        boolean firstIp = true;

        for (var entry : attempts.entrySet()) {
            String ip = entry.getKey();
            LinkedList<Long> ts = entry.getValue();

            ts.removeIf(t -> now - t > WINDOW_MS);
            if (ts.size() < THRESHOLD) blocked.remove(ip);
            int count = ts.size();

            String status = blocked.contains(ip)                       ? "BLOCKED"
                          : count >= (int) Math.ceil(THRESHOLD * 0.6) ? "WATCHING"
                          : "CLEAN";

            // Serialize timestamps array (oldest → newest, insertion order)
            StringBuilder tsArr = new StringBuilder("[");
            boolean firstTs = true;
            for (long t : ts) {
                if (!firstTs) tsArr.append(",");
                tsArr.append(t);
                firstTs = false;
            }
            tsArr.append("]");

            if (!firstIp) ips.append(",");
            ips.append(String.format(
                "{\"ip\":\"%s\",\"hits\":%d,\"status\":\"%s\",\"timestamps\":%s}",
                ip, count, status, tsArr
            ));
            firstIp = false;
        }
        ips.append("]");

        return String.format(
            "{\"threshold\":%d,\"window_ms\":%d,\"ips\":%s}",
            THRESHOLD, WINDOW_MS, ips
        );
    }
}
