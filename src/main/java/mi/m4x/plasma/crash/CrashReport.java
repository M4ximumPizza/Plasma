package mi.m4x.plasma.crash;

import java.awt.*;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Utility class to generate detailed crash reports for uncaught exceptions.
 * The report includes system information, environment variables, thread info, and stack trace.
 * Sensitive information such as usernames, user paths, and tokens are automatically redacted.
 *
 * @author M4ximumpizza
 * @since 1.0.0
 */
public class CrashReport {

    // Regex pattern to detect long alphanumeric strings that may be tokens or secrets
    private static final Pattern TOKEN_PATTERN = Pattern.compile("[A-Za-z0-9-_]{20,}");

    /**
     * Generates a crash report file with system info, environment variables, thread info, and stack trace.
     * Automatically redacts sensitive information such as usernames, user paths, and tokens.
     *
     * @param throwable   The exception that caused the crash.
     * @param description A brief description of what was happening at the time of the crash.
     */
    public static void generate(Throwable throwable, String description) {
        // Timestamp for unique crash report filename
        String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH.mm.ss").format(new Date());
        String fileName = "crash-report-" + timestamp + ".txt";

        StringBuilder report = new StringBuilder();
        report.append("==== CRASH REPORT ====\n");
        report.append("// The application encountered an unexpected error.\n\n");

        // Include human-readable timestamp and description of the crash
        report.append("Time: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\n");
        report.append("Description: ").append(description).append("\n\n");

        // SYSTEM INFORMATION: OS, Java, JVM, available processors
        report.append("== System Information ==\n");
        report.append("OS: ").append(System.getProperty("os.name"))
                .append(" ").append(System.getProperty("os.version"))
                .append(" (").append(System.getProperty("os.arch")).append(")\n");
        report.append("Java: ").append(System.getProperty("java.version"))
                .append(" (").append(System.getProperty("java.vendor")).append(")\n");
        report.append("JVM: ").append(System.getProperty("java.vm.name"))
                .append(" ").append(System.getProperty("java.vm.version")).append("\n");
        report.append("Available Processors: ").append(Runtime.getRuntime().availableProcessors()).append("\n");

        // MEMORY USAGE: heap and non-heap memory statistics
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        MemoryUsage heap = memoryBean.getHeapMemoryUsage();
        MemoryUsage nonHeap = memoryBean.getNonHeapMemoryUsage();
        report.append(String.format("Heap Memory: Used %d MB / Max %d MB / Committed %d MB\n",
                heap.getUsed() / (1024 * 1024),
                heap.getMax() / (1024 * 1024),
                heap.getCommitted() / (1024 * 1024)));
        report.append(String.format("Non-Heap Memory: Used %d MB / Committed %d MB\n",
                nonHeap.getUsed() / (1024 * 1024),
                nonHeap.getCommitted() / (1024 * 1024)));
        report.append("\n");

        // DISPLAY INFORMATION: screen resolution and refresh rate
        report.append("== Display Information ==\n");
        try {
            GraphicsDevice gd = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
            DisplayMode dm = gd.getDisplayMode();
            report.append("Resolution: ").append(dm.getWidth()).append("x").append(dm.getHeight()).append("\n");
            report.append("Refresh Rate: ").append(dm.getRefreshRate()).append(" Hz\n");
        } catch (Exception e) {
            report.append("Display Info: Unable to retrieve\n");
        }
        report.append("\n");

        // ENVIRONMENT VARIABLES: redact sensitive info such as user paths and tokens
        report.append("== Environment Variables ==\n");
        String username = System.getProperty("user.name");
        for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            // Skip variables that expose user/computer info
            if (key.equalsIgnoreCase("USERNAME") ||
                    key.equalsIgnoreCase("USERPROFILE") ||
                    key.equalsIgnoreCase("HOMEPATH") ||
                    key.equalsIgnoreCase("HOMEDRIVE") ||
                    key.equalsIgnoreCase("COMPUTERNAME") ||
                    key.equalsIgnoreCase("USERDOMAIN") ||
                    key.equalsIgnoreCase("LOGONSERVER") ||
                    key.equalsIgnoreCase("USERDOMAIN_ROAMINGPROFILE")) {
                continue;
            }

            // Replace occurrences of the username in any path with [REDACTED_USER]
            if (value != null && username != null) {
                value = value.replace(username, "[REDACTED_USER]");
            }

            // Redact environment variables likely to contain tokens or secrets
            if (key.toUpperCase().matches(".*(TOKEN|SECRET|KEY|PASSWORD|ACCESS|AUTH|GIT|GRADLE|AWS).*")) {
                value = "[REDACTED_TOKEN]";
            }

            // Redact any long token-like strings anywhere in the variable value
            if (value != null) {
                value = TOKEN_PATTERN.matcher(value).replaceAll("[REDACTED_TOKEN]");
            }

            report.append(key).append(" = ").append(value).append("\n");
        }
        report.append("\n");

        // THREAD INFORMATION: current thread name and ID
        report.append("== Thread Info ==\n");
        Thread currentThread = Thread.currentThread();
        report.append("Current Thread: ").append(currentThread.getName())
                .append(" (ID: ").append(currentThread.getId()).append(")\n\n");

        // STACK TRACE: full exception stack for debugging
        report.append("== Stack Trace ==\n");
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        report.append(sw.toString()).append("\n");

        // Write crash report to a timestamped text file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName))) {
            writer.write(report.toString());
            System.out.println("Crash report saved as " + fileName);
        } catch (IOException e) {
            System.err.println("Failed to write crash report: " + e.getMessage());
        }
    }
}
