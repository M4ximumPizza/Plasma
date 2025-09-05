# Plasma Utility Library

Plasma is a lightweight Java utility library providing helpful tools for caching, cryptography, crash reporting, and system probing. It is designed to simplify common tasks in Java applications with easy-to-use APIs.

## Features

- **Caching Utilities**: Infinite, TTL, and LRU memoization helpers for functions.
- **Cryptography Helpers**: SHA-256/SHA-512 hashing, HMAC, and secure random token generation.
- **Crash Reporting**: Detailed crash reports with system info and automatic sensitive data redaction.
- **System Probes**: Cross-platform CPU and GPU detection utilities.

## Installation

Add Plasma to your Gradle project:

```groovy
dependencies {
    implementation 'mi.m4x.plasma:plasma:1.0.0-SNAPSHOT'
}
```

## Usage

### Caching Example

```java
Function<Integer, Integer> memoized = Cache.memoize(x -> x * 2);
int result = memoized.apply(5); // Computes and caches result
```

### Cryptography Example

```java
String hash = CryptoUtils.sha256("Hello, World!");
String token = CryptoUtils.randomToken(16);
```

### Crash Reporting Example

```java
try {
    // risky code
} catch (Throwable t) {
    CrashReport.generate(t, "Crash during startup");
}
```

### System Probe Example

```java
ProcessorProbe.detectCpu();
GraphicsProbe.detectGraphicsAdapters();
```

## Contributing

Contributions are welcome! Please open issues or submit pull requests for improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.