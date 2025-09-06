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
    private static final Logger LOGGER = LoggerFactory.getLogger(ProcessorProbe.class);

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
     * Detects CPU information on Windows using PowerShell (Get-CimInstance).
     * Outputs a single line: Name;Cores;LogicalProcessors
     */
    private static void detectWindowsCpu() {
        try {
            String psCommand =
                    "Get-CimInstance Win32_Processor | " +
                            "Select-Object -First 1 -Property Name,NumberOfCores,NumberOfLogicalProcessors | " +
                            "ForEach-Object { ($_.Name + ';' + $_.NumberOfCores + ';' + $_.NumberOfLogicalProcessors) }";

            Process process = new ProcessBuilder("powershell", "-Command", psCommand)
                    .redirectErrorStream(true)
                    .start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line = reader.readLine();
                if (line != null && !line.isBlank()) {
                    String[] parts = line.split(";");
                    String name = parts.length > 0 ? parts[0].trim() : "Unknown";
                    String cores = parts.length > 1 ? parts[1].trim() : "Unknown";
                    String logicalProcessors = parts.length > 2 ? parts[2].trim() : "Unknown";
                    String arch = System.getProperty("os.arch");

                    System.out.println("CPU Name: " + name);
                    System.out.println("Number of Cores: " + cores);
                    System.out.println("Number of Logical Processors: " + logicalProcessors);
                    System.out.println("Architecture: " + arch);
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to detect CPU information on Windows");
            e.printStackTrace();
        }
    }

    /**
     * Detects CPU information on macOS using sysctl.
     * Gets brand string, physical cores, and logical processors.
     */
    private static void detectMacCpu() {
        try {
            Process brandProcess = new ProcessBuilder("sysctl", "-n", "machdep.cpu.brand_string").start();
            String name;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(brandProcess.getInputStream()))) {
                name = reader.readLine();
            }

            // Physical cores
            Process coresProcess = new ProcessBuilder("sysctl", "-n", "hw.physicalcpu").start();
            String cores;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(coresProcess.getInputStream()))) {
                cores = reader.readLine();
            }

            // Logical processors
            Process logicalProcess = new ProcessBuilder("sysctl", "-n", "hw.logicalcpu").start();
            String logicalProcessors;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(logicalProcess.getInputStream()))) {
                logicalProcessors = reader.readLine();
            }

            // Print detected CPU info
            System.out.println("CPU Name: " + (name != null ? name : "Unknown"));
            System.out.println("Number of Cores: " + (cores != null ? cores : "Unknown"));
            System.out.println("Number of Logical Processors: " + (logicalProcessors != null ? logicalProcessors : "Unknown"));
            System.out.println("Architecture: " + System.getProperty("os.arch"));

        } catch (Exception e) {
            System.err.println("Failed to detect CPU information on macOS");
            e.printStackTrace();
        }
    }

    /**
     * Detects CPU information on Linux using the 'lscpu' command.
     * Extracts CPU model, physical cores, logical processors, and architecture.
     */
    private static void detectLinuxCpu() {
        try {
            Process process = new ProcessBuilder("lscpu").start();

            String name = "Unknown";
            String coresPerSocket = "Unknown";
            String sockets = "1";
            String logicalProcessors = "Unknown";
            String architecture = System.getProperty("os.arch");

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("Model name:")) {
                        name = line.split(":", 2)[1].trim();
                    } else if (line.startsWith("CPU(s):")) {
                        logicalProcessors = line.split(":", 2)[1].trim();
                    } else if (line.startsWith("Core(s) per socket:")) {
                        coresPerSocket = line.split(":", 2)[1].trim();
                    } else if (line.startsWith("Socket(s):")) {
                        sockets = line.split(":", 2)[1].trim();
                    } else if (line.startsWith("Architecture:")) {
                        architecture = line.split(":", 2)[1].trim();
                    }
                }
            }

            // Calculate total physical cores
            String totalCores = "Unknown";
            try {
                int cores = Integer.parseInt(coresPerSocket);
                int sock = Integer.parseInt(sockets);
                totalCores = String.valueOf(cores * sock);
            } catch (NumberFormatException ignored) {}

            // Print detected CPU info
            System.out.println("CPU Name: " + name);
            System.out.println("Number of Cores: " + totalCores);
            System.out.println("Number of Logical Processors: " + logicalProcessors);
            System.out.println("Architecture: " + architecture);

        } catch (Exception e) {
            System.err.println("Failed to detect CPU information on Linux");
            e.printStackTrace();
        }
    }
}
