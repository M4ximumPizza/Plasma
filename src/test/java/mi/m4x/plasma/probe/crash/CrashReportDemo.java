package mi.m4x.plasma.probe.crash;

import mi.m4x.plasma.crash.CrashReport;

public class CrashReportDemo {

    public static void main(String[] args) {
        Thread crashThread = new Thread(() -> {
            try {
                simulateCrash();
            } catch (Throwable e) {
                CrashReport.generate(e, "Another crash report for testing purposes");
            }
        }, "Test Thread");

        crashThread.start();

        try {
            crashThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private static void simulateCrash() {
        throw new RuntimeException("Simulated crash for testing purposes!");
    }
}
