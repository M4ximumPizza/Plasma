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
 * @author M4ximumpizza
 * @since 1.0.0
 */
public class GraphicsProbe {

    // Logger for outputting information, warnings, and errors
    private static final Logger LOGGER = LoggerFactory.getLogger(GraphicsProbe.class);

    // List to store detected graphics adapters
    private static final List<GraphicsAdapter> ADAPTERS = new ArrayList<>();

    // -----------------------------------------
    // Public API
    // -----------------------------------------

    /**
     * Returns an unmodifiable list of detected graphics adapters.
     * @return list of GraphicsAdapter objects
     */
    public static List<GraphicsAdapter> getAdapters() {
        return Collections.unmodifiableList(ADAPTERS);
    }

    /**
     * Main entry point for detecting graphics adapters on the current OS.
     * Automatically chooses the detection method based on OS type.
     * Adds a virtual GPU fallback if running in a VM and no real GPU is found.
     */
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

            // If nothing detected on Linux, add a virtual GPU as fallback (common in VMs)
            if (ADAPTERS.isEmpty() && (os.contains("nix") || os.contains("nux") || os.contains("aix"))) {
                LOGGER.info("No real GPU detected, adding Virtual GPU fallback for VM.");
                ADAPTERS.add(new GraphicsAdapter("Virtual GPU (VM)", "UNKNOWN"));
            }

            // Log all detected adapters
            logDetectedAdapters();
        } catch (Exception e) {
            LOGGER.error("Failed to detect graphics adapters", e);
        }
    }

    // -----------------------------------------
    // Detection Implementations
    // -----------------------------------------

    /**
     * Detects graphics adapters on Windows using WMIC.
     * Extracts adapter name and PCI device ID from the PNPDeviceID string.
     */
    private static void detectWindowsAdapters() {
        try {
            Process process = new ProcessBuilder("wmic", "path", "win32_videocontroller", "get", "Name,PNPDeviceID")
                    .redirectErrorStream(true)
                    .start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                reader.lines()
                        .map(String::trim)
                        .filter(line -> !line.isEmpty() && !line.startsWith("Name"))
                        .forEach(line -> {
                            String name = "";
                            String pciId = "UNKNOWN";

                            // Split the line into name and PNPDeviceID
                            String[] parts = line.split("\\s{2,}");
                            if (parts.length >= 2) {
                                name = parts[0];
                                String pnp = parts[1];
                                // Extract vendor (VEN) and device (DEV) IDs if available
                                if (pnp.contains("VEN_") && pnp.contains("DEV_")) {
                                    String ven = pnp.substring(pnp.indexOf("VEN_") + 4, pnp.indexOf("VEN_") + 8);
                                    String dev = pnp.substring(pnp.indexOf("DEV_") + 4, pnp.indexOf("DEV_") + 8);
                                    pciId = "0x" + ven.toUpperCase() + ":0x" + dev.toUpperCase();
                                }
                            } else {
                                name = line;
                            }

                            ADAPTERS.add(new GraphicsAdapter(name, pciId));
                        });
            }
        } catch (Exception e) {
            LOGGER.error("Error detecting Windows graphics adapters", e);
        }
    }

    /**
     * Detects graphics adapters on Linux by reading PCI device information.
     * Maps vendor IDs to known GPU manufacturers (NVIDIA, AMD, Intel).
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
     * Detects graphics adapters on macOS by parsing `system_profiler SPDisplaysDataType` output.
     */
    private static void detectMacAdapters() {
        try {
            Process process = new ProcessBuilder("system_profiler", "SPDisplaysDataType").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    // Look for lines containing the GPU name
                    if (line.startsWith("Chipset Model:") || line.startsWith("Graphics/Displays:")) {
                        String name = line.contains(":") ? line.split(":")[1].trim() : line;
                        if (!name.isEmpty() && !name.equalsIgnoreCase("Graphics/Displays")) {
                            ADAPTERS.add(new GraphicsAdapter(name, "UNKNOWN"));
                        }
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

    /**
     * Logs the list of detected graphics adapters.
     * If none detected, prints a warning.
     */
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

    /**
     * Represents a detected graphics adapter.
     * @param name Human-readable GPU name
     * @param pciId PCI vendor:device ID (or "UNKNOWN" if unavailable)
     */
    public record GraphicsAdapter(
            String name,
            String pciId
    ) {}
}
