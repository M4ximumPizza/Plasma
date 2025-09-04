package mi.m4x.plasma.probe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Simple cross-platform graphics adapter detection (Windows, Linux, macOS).
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

            logDetectedAdapters();
        } catch (Exception e) {
            LOGGER.error("Failed to detect graphics adapters", e);
        }
    }

    // -----------------------------------------
    // Detection Implementations
    // -----------------------------------------

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

                            // Split into name and PNPDeviceID, using multiple spaces as separator
                            String[] parts = line.split("\\s{2,}");
                            if (parts.length >= 2) {
                                name = parts[0];
                                String pnp = parts[1];

                                // Extract PCI VEN/DEV if present
                                if (pnp.contains("VEN_") && pnp.contains("DEV_")) {
                                    String ven = pnp.substring(pnp.indexOf("VEN_") + 4, pnp.indexOf("VEN_") + 8);
                                    String dev = pnp.substring(pnp.indexOf("DEV_") + 4, pnp.indexOf("DEV_") + 8);
                                    pciId = "0x" + ven.toUpperCase() + ":0x" + dev.toUpperCase();
                                }
                            } else {
                                // If split fails, fallback to the whole line as name
                                name = line;
                            }

                            ADAPTERS.add(new GraphicsAdapter(name, pciId));
                        });
            }
        } catch (Exception e) {
            LOGGER.error("Error detecting Windows graphics adapters", e);
        }
    }

    private static void detectLinuxAdapters() {
        try {
            Process process = new ProcessBuilder("lspci", "-nn").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                reader.lines()
                        .filter(line -> line.contains("VGA") || line.contains("3D"))
                        .forEach(GraphicsProbe::parseLinuxAdapter);
            }
        } catch (Exception e) {
            LOGGER.error("Error detecting Linux graphics adapters", e);
        }
    }

    private static void detectMacAdapters() {
        try {
            Process process = new ProcessBuilder("system_profiler", "SPDisplaysDataType").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
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
    // Parsing Helpers
    // -----------------------------------------

    private static void parseWindowsAdapter(String line) {
        String[] parts = line.trim().split("\\s{2,}");
        String name = parts[0];
        ADAPTERS.add(new GraphicsAdapter(name, "UNKNOWN"));
    }

    private static void parseLinuxAdapter(String line) {
        String name = line.substring(line.indexOf(": ") + 2).trim();
        String pciId = line.replaceAll(".*\\[([\\da-f]{4}):.*", "$1");
        ADAPTERS.add(new GraphicsAdapter(name, "0x" + pciId.toUpperCase()));
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
