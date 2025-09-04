package mi.m4x.plasma.probe.cpu;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Locale;

public class ProcessorProbe {
    private static Logger LOGGER = LoggerFactory.getLogger(ProcessorProbe.class);
    public static void detectCpu() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);

        if (os.contains("win")) {
            detectWindowsCpu();
        } else if (os.contains("mac")) {
            detectMacCpu();
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            detectLinuxCpu();
        } else {
            System.out.println("Unsupported OS: " + os);
        }
    }

    private static void detectWindowsCpu() {
        try {
            Process process = new ProcessBuilder("wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors")
                    .redirectErrorStream(true).start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                reader.lines()
                        .filter(line -> !line.trim().isEmpty() && !line.startsWith("Name"))
                        .forEach(line -> {
                            String[] parts = line.trim().split("\\s{2,}");
                            String name = parts[0];
                            String cores = parts.length > 1 ? parts[1] : "Unknown";
                            String logicalProcessors = parts.length > 2 ? parts[2] : "Unknown";
                            String architecture = System.getenv("PROCESSOR_ARCHITECTURE");

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

    private static void detectMacCpu() {
        try {
            Process process = new ProcessBuilder("sysctl", "-n", "machdep.cpu.brand_string").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String name = reader.readLine();
                int cores = Runtime.getRuntime().availableProcessors();
                System.out.println("CPU Name: " + name);
                System.out.println("Number of Cores: " + cores);
                System.out.println("Architecture: " + System.getProperty("os.arch"));
            }
        } catch (Exception e) {
            System.err.println("Failed to detect CPU information on macOS");
            e.printStackTrace();
        }
    }

    private static void detectLinuxCpu() {
        try {
            Process process = new ProcessBuilder("lscpu").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                String name = "Unknown";
                String cores = "Unknown";
                String logicalProcessors = "Unknown";
                String architecture = "Unknown";

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
