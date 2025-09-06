package mi.m4x.plasma.probe.gpu;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Simple cross-platform graphics adapter detection (Windows, Linux, macOS),
 * with automatic virtual GPU fallback for VMs.
 *
 * Uses dxdiag on Windows (WMIC is deprecated and removed in Win11+).
 *
 * @author M4ximumpizza
 * @since 1.0.0
 */
public class GraphicsProbe {

    private static final Logger LOGGER = LoggerFactory.getLogger(GraphicsProbe.class);

    private static final List<GraphicsAdapter> ADAPTERS = new ArrayList<>();

    // -----------------------------------------
    // Public API
    // -----------------------------------------

    public static List<GraphicsAdapter> getAdapters() {
        return Collections.unmodifiableList(ADAPTERS);
    }

    public static void detectGraphicsAdapters() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
        try {
            LOGGER.info("Starting graphics adapter detection on OS: {}", os);

            if (os.contains("win")) {
                detectWindowsAdapters();
            } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
                detectLinuxAdapters();
            } else if (os.contains("mac")) {
                detectMacAdapters();
            } else {
                LOGGER.warn("Unsupported OS: {}", os);
            }

            // Fallback for VMs
            if (ADAPTERS.isEmpty() && (os.contains("nix") || os.contains("nux") || os.contains("aix"))) {
                LOGGER.info("No real GPU detected, adding Virtual GPU fallback for VM.");
                ADAPTERS.add(new GraphicsAdapter("Virtual GPU (VM)", "UNKNOWN"));
            }

            logDetectedAdapters();
        } catch (Exception e) {
            LOGGER.error("Failed to detect graphics adapters", e);
        }
    }

    // -----------------------------------------
    // Detection Implementations
    // -----------------------------------------

    /**
     * Detects graphics adapters on Windows using dxdiag (WMIC is deprecated).
     */
    private static void detectWindowsAdapters() {
        try {
            String psCommand =
                    "Get-CimInstance Win32_VideoController | " +
                            "ForEach-Object { $_.Name + ';' + $_.PNPDeviceID }";

            Process process = new ProcessBuilder("powershell", "-Command", psCommand)
                    .redirectErrorStream(true)
                    .start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;

                    String[] parts = line.split(";", 2);
                    String name = parts.length > 0 ? parts[0].trim() : "Unknown GPU";
                    String pciId = "UNKNOWN";

                    if (parts.length > 1) {
                        String pnp = parts[1];
                        if (pnp.contains("VEN_") && pnp.contains("DEV_")) {
                            String ven = pnp.substring(pnp.indexOf("VEN_") + 4, pnp.indexOf("VEN_") + 8);
                            String dev = pnp.substring(pnp.indexOf("DEV_") + 4, pnp.indexOf("DEV_") + 8);
                            pciId = "0x" + ven.toUpperCase() + ":0x" + dev.toUpperCase();
                        }
                    }

                    ADAPTERS.add(new GraphicsAdapter(name, pciId));
                }
            }

        } catch (Exception e) {
            LOGGER.error("Error detecting Windows graphics adapters", e);
        }
    }


    /**
     * Detects graphics adapters on Linux via sysfs PCI devices.
     */
    private static void detectLinuxAdapters() {
        File pciRoot = new File("/sys/bus/pci/devices/");
        if (!pciRoot.exists() || !pciRoot.isDirectory()) {
            LOGGER.warn("No graphics adapters detected.");
            return;
        }

        File[] devices = pciRoot.listFiles();
        if (devices == null) {
            LOGGER.warn("No graphics adapters detected.");
            return;
        }

        for (File device : devices) {
            File vendorFile = new File(device, "vendor");
            File deviceFile = new File(device, "device");

            if (!vendorFile.exists() || !deviceFile.exists()) continue;

            try {
                String vendor = new String(Files.readAllBytes(vendorFile.toPath())).trim();
                String dev = new String(Files.readAllBytes(deviceFile.toPath())).trim();

                String name = switch (vendor) {
                    case "0x10de" -> "NVIDIA GPU";
                    case "0x1002" -> "AMD GPU";
                    case "0x8086" -> "Intel GPU";
                    default -> "Unknown GPU " + vendor + ":" + dev;
                };

                ADAPTERS.add(new GraphicsAdapter(name, vendor + ":" + dev));
            } catch (Exception ignored) {}
        }

        if (ADAPTERS.isEmpty()) {
            LOGGER.warn("No graphics adapters detected.");
        }
    }

    /**
     * Detects graphics adapters on macOS via system_profiler.
     */
    private static void detectMacAdapters() {
        try {
            Process process = new ProcessBuilder("system_profiler", "SPDisplaysDataType").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("Chipset Model:")) {
                        String name = line.split(":", 2)[1].trim();
                        ADAPTERS.add(new GraphicsAdapter(name, "UNKNOWN"));
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error detecting macOS graphics adapters", e);
        }
    }

    // -----------------------------------------
    // Logging Helpers
    // -----------------------------------------

    private static void logDetectedAdapters() {
        if (ADAPTERS.isEmpty()) {
            LOGGER.warn("No graphics adapters detected.");
            return;
        }

        LOGGER.info("Detected {} graphics adapter(s):", ADAPTERS.size());
        for (GraphicsAdapter adapter : ADAPTERS) {
            LOGGER.info("- {} | PCI: {}", adapter.name(), adapter.pciId());
        }
    }

    // -----------------------------------------
    // GraphicsAdapter Record
    // -----------------------------------------

    public record GraphicsAdapter(
            String name,
            String pciId
    ) {}
}
