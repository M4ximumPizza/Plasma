package mi.m4x.plasma.probe;

import mi.m4x.plasma.crash.CrashReport;
import mi.m4x.plasma.probe.cpu.ProcessorProbe;
import mi.m4x.plasma.probe.crash.CrashReportDemo;
import mi.m4x.plasma.probe.gpu.GraphicsProbe;

public class Main {
    public static void main(String[] args) {
        ProcessorProbe.detectCpu();
        GraphicsProbe.detectGraphicsAdapters();
    }
}
