package mi.m4x.plasma.cache;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Utility class providing memoization helpers that wrap functions
 * with caching behavior.
 *
 * Provides:
 * - Basic infinite memoization
 * - TTL-based memoization
 * - LRU-based memoization
 *
 * @author M4ximumpizza
 * @since 1.0.0
 */
public class Cache {

    /**
     * Wraps a function with infinite memoization.
     *
     * Stores results indefinitely. Use only if the input space is bounded,
     * otherwise memory usage may grow without limit.
     */
    public static <T, R> Function<T, R> memoize(Function<T, R> function) {
        var cache = new ConcurrentHashMap<T, R>();
        return input -> cache.computeIfAbsent(input, function);
    }

    /**
     * Wraps a function with TTL (time-to-live) memoization.
     *
     * Cached results expire after the given TTL. Expired entries
     * are removed lazily on access and periodically in the background.
     */
    public static <T, R> Function<T, R> memoizeTTL(Function<T, R> function, long ttlMillis) {
        var cache = new TTLCache<T, R>(ttlMillis);
        return input -> {
            R val = cache.get(input);
            if (val == null) {
                val = function.apply(input);
                cache.put(input, val);
            }
            return val;
        };
    }

    /**
     * Wraps a function with LRU (least recently used) memoization.
     *
     * Stores up to {@code maxSize} results. When the cache exceeds
     * the maximum size, the least recently used entry is evicted.
     */
    public static <T, R> Function<T, R> memoizeLRU(Function<T, R> function, int maxSize) {
        var cache = new LRUCache<T, R>(maxSize);
        return input -> {
            synchronized (cache) { // LRUCache is not thread-safe
                return cache.computeIfAbsent(input, function);
            }
        };
    }
}
