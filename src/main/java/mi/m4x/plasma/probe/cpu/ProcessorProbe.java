package mi.m4x.plasma.probe.cpu;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Locale;

/**
 * Cross-platform CPU detection utility.
 * Detects CPU information such as name, number of cores, logical processors,
 * and architecture for Windows, macOS, and Linux systems.
 *
 * @author M4ximumpizza
 * @since 1.0.0
 */
public class ProcessorProbe {

    // Logger for debugging and info messages
    private static Logger LOGGER = LoggerFactory.getLogger(ProcessorProbe.class);

    /**
     * Main entry point to detect CPU information.
     * Determines OS type and delegates to the appropriate OS-specific method.
     */
    public static void detectCpu() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);

        if (os.contains("win")) {
            detectWindowsCpu();
        } else if (os.contains("mac")) {
            detectMacCpu();
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            detectLinuxCpu();
        } else {
            // Unsupported OS fallback
            System.out.println("Unsupported OS: " + os);
        }
    }

    /**
     * Detects CPU information on Windows using WMIC.
     * Parses Name, Number of Cores, and Number of Logical Processors.
     * Architecture is retrieved from environment variable PROCESSOR_ARCHITECTURE.
     */
    private static void detectWindowsCpu() {
        try {
            Process process = new ProcessBuilder(
                    "wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors"
            ).redirectErrorStream(true).start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                reader.lines()
                        // Filter out empty lines and header row
                        .filter(line -> !line.trim().isEmpty() && !line.startsWith("Name"))
                        .forEach(line -> {
                            String[] parts = line.trim().split("\\s{2,}"); // Split columns by multiple spaces
                            String name = parts[0]; // CPU name
                            String cores = parts.length > 1 ? parts[1] : "Unknown"; // Physical cores
                            String logicalProcessors = parts.length > 2 ? parts[2] : "Unknown"; // Logical cores
                            String architecture = System.getenv("PROCESSOR_ARCHITECTURE"); // CPU architecture

                            // Print detected CPU info
                            System.out.println("CPU Name: " + name);
                            System.out.println("Number of Cores: " + cores);
                            System.out.println("Number of Logical Processors: " + logicalProcessors);
                            System.out.println("Architecture: " + architecture);
                        });
            }
        } catch (Exception e) {
            System.err.println("Failed to detect CPU information on Windows");
            e.printStackTrace();
        }
    }

    /**
     * Detects CPU information on macOS using sysctl.
     * CPU name is retrieved from machdep.cpu.brand_string.
     * Number of cores is approximated using Runtime.getRuntime().availableProcessors().
     * Architecture is retrieved via os.arch system property.
     */
    private static void detectMacCpu() {
        try {
            Process process = new ProcessBuilder(
                    "sysctl", "-n", "machdep.cpu.brand_string"
            ).start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String name = reader.readLine(); // CPU model name
                int cores = Runtime.getRuntime().availableProcessors(); // Number of cores (logical)

                // Print detected CPU info
                System.out.println("CPU Name: " + name);
                System.out.println("Number of Cores: " + cores);
                System.out.println("Architecture: " + System.getProperty("os.arch"));
            }
        } catch (Exception e) {
            System.err.println("Failed to detect CPU information on macOS");
            e.printStackTrace();
        }
    }

    /**
     * Detects CPU information on Linux using the 'lscpu' command.
     * Parses CPU model name, physical cores, logical processors, and architecture.
     */
    private static void detectLinuxCpu() {
        try {
            Process process = new ProcessBuilder("lscpu").start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                String name = "Unknown";
                String cores = "Unknown";
                String logicalProcessors = "Unknown";
                String architecture = "Unknown";

                // Read lscpu output line by line and extract relevant information
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("Model name:")) {
                        name = line.split(":", 2)[1].trim();
                    } else if (line.startsWith("CPU(s):")) {
                        logicalProcessors = line.split(":", 2)[1].trim();
                    } else if (line.startsWith("Core(s) per socket:")) {
                        cores = line.split(":", 2)[1].trim();
                    } else if (line.startsWith("Architecture:")) {
                        architecture = line.split(":", 2)[1].trim();
                    }
                }

                // Print detected CPU info
                System.out.println("CPU Name: " + name);
                System.out.println("Number of Cores: " + cores);
                System.out.println("Number of Logical Processors: " + logicalProcessors);
                System.out.println("Architecture: " + architecture);
            }
        } catch (Exception e) {
            System.err.println("Failed to detect CPU information on Linux");
            e.printStackTrace();
        }
    }
}
