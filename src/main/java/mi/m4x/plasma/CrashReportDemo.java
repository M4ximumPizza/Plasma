package mi.m4x.plasma;

import mi.m4x.plasma.crash.CrashReport;

public class CrashReportDemo {

    public static void main(String[] args) {
        Thread crashThread = new Thread(() -> {
            try {
                simulateCrash();
            } catch (Throwable e) {
                CrashReport.generate(e, "Another crash report for testing purposes");
            }
        }, "gay");

        // Set thread as daemon
        crashThread.setDaemon(true);

        crashThread.start();

        try {
            crashThread.join(); // optional; joining a daemon thread is okay but not required
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private static void simulateCrash() {
        throw new RuntimeException("Simulated crash for testing purposes!");
    }
}
