package mi.m4x.plasma.cache;

import java.util.function.Function;

public class CacheTest{
    public static void main(String[] args) throws InterruptedException {
        System.out.println("=== Testing memoize ===");
        Function<Integer, Integer> memoized = Cache.memoize(x -> {
            System.out.println("Computing " + x);
            return x * 2;
        });
        System.out.println(memoized.apply(5));
        System.out.println(memoized.apply(5));
        System.out.println(memoized.apply(10));

        System.out.println("\n=== Testing memoizeTTL ===");
        Function<Integer, Integer> memoizedTTL = Cache.memoizeTTL(x -> {
            System.out.println("Computing TTL " + x);
            return x * 3;
        }, 500);
        System.out.println(memoizedTTL.apply(1));
        System.out.println(memoizedTTL.apply(1));
        Thread.sleep(600); // wait for TTL expiration
        System.out.println(memoizedTTL.apply(1));

        System.out.println("\n=== Testing memoizeLRU ===");
        Function<Integer, Integer> memoizedLRU = Cache.memoizeLRU(x -> {
            System.out.println("Computing LRU " + x);
            return x * 4;
        }, 2);
        memoizedLRU.apply(1);
        memoizedLRU.apply(2);
        memoizedLRU.apply(3); // should evict 1
        memoizedLRU.apply(1); // recompute

        System.out.println("\n=== Testing LRUCache hit/miss ===");
        LRUCache<Integer, String> lruCache = new LRUCache<>(2);
        lruCache.put(1, "A");
        lruCache.put(2, "B");
        lruCache.get(1);
        lruCache.get(3);
        System.out.println("Hits: " + lruCache.getHits());
        System.out.println("Misses: " + lruCache.getMisses());

        System.out.println("\n=== Testing TTLCache ===");
        TTLCache<Integer, String> ttlCache = new TTLCache<>(500);
        ttlCache.put(1, "A");
        ttlCache.put(2, "B");
        System.out.println(ttlCache.get(1));
        System.out.println(ttlCache.get(2));
        Thread.sleep(600); // wait for TTL expiration
        System.out.println(ttlCache.get(1));
        System.out.println("Hits: " + ttlCache.getHits());
        System.out.println("Misses: " + ttlCache.getMisses());
    }
}
