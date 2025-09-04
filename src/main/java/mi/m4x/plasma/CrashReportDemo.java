package mi.m4x.plasma;

import mi.m4x.plasma.crash.CrashReport;

public class CrashReportDemo {

    public static void main(String[] args) {
        try {
            simulateCrash();
        } catch (Throwable e) {
            CrashReport.generate(e, "Another crash report for testing purposes");
        }
    }

    private static void simulateCrash() {
        // This will intentionally crash
        throw new RuntimeException("Simulated crash for testing purposes!");
    }
}
