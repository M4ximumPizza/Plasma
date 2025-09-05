package mi.m4x.plasma.cache;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A cache that stores entries for a fixed duration (time-to-live).
 *
 * - Each entry is associated with an expiration timestamp.
 * - Expired entries are removed on access and periodically by a background thread.
 * - Thread-safe for concurrent access.
 * - Tracks hit/miss statistics.
 *
 * @author M4ximumpizza
 * @since 1.0.0
 */
public class TTLCache<K, V> {
    private final ConcurrentHashMap<K, CacheEntry<V>> cache = new ConcurrentHashMap<>();
    private final long ttlMillis;
    private final ScheduledExecutorService cleaner;
    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();

    /**
     * @param ttlMillis lifetime (in milliseconds) for each cache entry
     */
    public TTLCache(long ttlMillis) {
        this.ttlMillis = ttlMillis;
        this.cleaner = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "TTLCache-Cleaner");
            t.setDaemon(true);
            return t;
        });
        // Run cleanup periodically
        cleaner.scheduleAtFixedRate(this::cleanup, ttlMillis, ttlMillis, TimeUnit.MILLISECONDS);
    }

    /** Inserts a value with expiration timestamp. */
    public void put(K key, V value) {
        cache.put(key, new CacheEntry<>(value, System.currentTimeMillis() + ttlMillis));
    }

    /** Retrieves a value if present and not expired, else returns null. */
    public V get(K key) {
        CacheEntry<V> entry = cache.get(key);
        if (entry == null || entry.isExpired()) {
            cache.remove(key);
            misses.incrementAndGet();
            return null;
        }
        hits.incrementAndGet();
        return entry.value;
    }

    /** @return true if key exists and is not expired */
    public boolean contains(K key) {
        return get(key) != null;
    }

    /** Removes a specific entry. */
    public void remove(K key) {
        cache.remove(key);
    }

    /** Clears the cache. */
    public void clear() {
        cache.clear();
    }

    /** @return number of entries currently stored (may include expired ones until cleanup runs) */
    public int size() {
        return cache.size();
    }

    /** @return number of successful lookups */
    public long getHits() {
        return hits.get();
    }

    /** @return number of failed lookups */
    public long getMisses() {
        return misses.get();
    }

    /** Background cleanup: removes expired entries. */
    private void cleanup() {
        long now = System.currentTimeMillis();
        cache.entrySet().removeIf(e -> e.getValue().expiryTime < now);
    }

    /** Internal wrapper for a cached value and its expiration timestamp. */
    private static class CacheEntry<V> {
        final V value;
        final long expiryTime;

        CacheEntry(V value, long expiryTime) {
            this.value = value;
            this.expiryTime = expiryTime;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }
}
