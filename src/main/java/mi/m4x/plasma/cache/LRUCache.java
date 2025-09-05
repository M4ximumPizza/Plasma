package mi.m4x.plasma.cache;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A least-recently-used (LRU) cache backed by {@link LinkedHashMap}.
 *
 * - Retains up to {@code maxSize} entries.
 * - Evicts the least recently accessed entry when capacity is exceeded.
 * - Tracks hit/miss statistics.
 *
 * ⚠️ Not thread-safe. Wrap with {@code synchronized} if used concurrently.
 *
 *
 * @author M4ximumpizza
 * @since 1.0.0
 */
public class LRUCache<K, V> extends LinkedHashMap<K, V> {
    private final int maxSize;
    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();

    /**
     * @param maxSize maximum number of entries to retain before evicting
     */
    public LRUCache(int maxSize) {
        super(maxSize, 0.75f, true); // accessOrder = true for LRU
        this.maxSize = maxSize;
    }

    /** Evicts eldest entry when size exceeds max capacity. */
    @Override
    protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        return size() > maxSize;
    }

    /** Overridden to track hit/miss statistics. */
    @Override
    public V get(Object key) {
        V val = super.get(key);
        if (val == null) {
            misses.incrementAndGet();
        } else {
            hits.incrementAndGet();
        }
        return val;
    }

    /** @return number of successful lookups */
    public long getHits() {
        return hits.get();
    }

    /** @return number of failed lookups */
    public long getMisses() {
        return misses.get();
    }
}
