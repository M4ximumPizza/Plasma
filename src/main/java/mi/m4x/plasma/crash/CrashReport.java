package mi.m4x.plasma.crash;

import java.awt.*;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CrashReport {
    public static void generate(Throwable throwable, String description) {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH.mm.ss").format(new Date());
        String fileName = "crash-report-" + timestamp + ".txt";

        StringBuilder report = new StringBuilder();
        report.append("---- Crash Report ----\n");
        report.append("// Oops. Something went wrong!\n\n");

        report.append("Time: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\n");
        report.append("Description: ").append(description).append("\n\n");

        // System info
        report.append("-- System Details --\n");
        report.append("Java Version: ").append(System.getProperty("java.version")).append("\n");
        report.append("Java Vendor: ").append(System.getProperty("java.vendor")).append("\n");
        report.append("Java Home: ").append(System.getProperty("java.home")).append("\n");
        report.append("Java VM: ").append(System.getProperty("java.vm.name")).append("\n\n");

        report.append("Operating System: ").append(System.getProperty("os.name"))
                .append(" ").append(System.getProperty("os.version"))
                .append(" (").append(System.getProperty("os.arch")).append(")\n");

        report.append("CPU Cores: ").append(Runtime.getRuntime().availableProcessors()).append("\n");
        report.append("Max Memory: ").append(Runtime.getRuntime().maxMemory() / (1024 * 1024)).append(" MB\n");
        report.append("Total Memory: ").append(Runtime.getRuntime().totalMemory() / (1024 * 1024)).append(" MB\n");
        report.append("Free Memory: ").append(Runtime.getRuntime().freeMemory() / (1024 * 1024)).append(" MB\n");

        // Display info
        try {
            GraphicsDevice gd = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
            DisplayMode dm = gd.getDisplayMode();
            report.append("Display Resolution: ").append(dm.getWidth()).append("x").append(dm.getHeight()).append("\n");
            report.append("Refresh Rate: ").append(dm.getRefreshRate()).append(" Hz\n");
        } catch (Exception e) {
            report.append("Display Info: Unable to retrieve\n");
        }

        // Stack trace
        report.append("-- Stack Trace --\n");
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        report.append(sw.toString()).append("\n");

        // Write to file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName))) {
            writer.write(report.toString());
            System.out.println("Crash report saved as " + fileName);
        } catch (IOException e) {
            System.err.println("Failed to write crash report: " + e.getMessage());
        }
    }
}