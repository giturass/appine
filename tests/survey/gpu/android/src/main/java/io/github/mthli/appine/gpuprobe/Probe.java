package io.github.mthli.appine.gpuprobe;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;

public final class Probe extends Instrumentation {
    private String path;

    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        path = args.getString("path", "dma-buf");
        start();
    }

    private static native String roundTrip(int path);

    @Override public void onStart() {
        System.loadLibrary("gpuprobe");
        String report;
        switch (path) {
            case "dma-buf": report = roundTrip(0); break;
            case "opaque-fd": report = roundTrip(1); break;
            case "dedicated-control": report = roundTrip(2); break;
            case "android-blob": report = roundTrip(3); break;
            case "cpu-export-blob": report = roundTrip(4); break;
            default: report = "Unknown path: " + path;
        }
        Bundle result = new Bundle();
        result.putString(REPORT_KEY_STREAMRESULT, "\n" + report);
        finish(report.endsWith("PASS\n") ? Activity.RESULT_OK : Activity.RESULT_CANCELED, result);
    }
}
