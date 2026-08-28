package com.example.accelerometer;

import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.util.Log;
/* loaded from: /home/kali/DroidForensix/analysis/recovered/RTO_recovered.dex */
public class AccelerometerEventListener implements SensorEventListener {
    public static float[] cachedValues;
    private final boolean isLogEnabled;

    @Override // android.hardware.SensorEventListener
    public void onAccuracyChanged(Sensor sensor, int i) {
    }

    public AccelerometerEventListener(boolean z) {
        this.isLogEnabled = z;
    }

    @Override // android.hardware.SensorEventListener
    public void onSensorChanged(SensorEvent sensorEvent) {
        if (sensorEvent.sensor.getType() == 1) {
            float f = sensorEvent.values[0];
            float f2 = sensorEvent.values[1];
            float f3 = sensorEvent.values[2];
            float[] fArr = cachedValues;
            if (fArr == null) {
                cachedValues = new float[4];
            } else if (Math.abs(fArr[0] - f) > 0.005d || Math.abs(cachedValues[1] - f2) > 0.005d || Math.abs(cachedValues[2] - f3) > 0.005d) {
                cachedValues[3] = 1.0f;
            }
            float[] fArr2 = cachedValues;
            fArr2[0] = f;
            fArr2[1] = f2;
            fArr2[2] = f3;
            if (this.isLogEnabled) {
                Log.v("accelerometer", String.format("X: %.4f\nY: %.4f\nZ: %.4f\nFLAG: %.1f", Float.valueOf(f), Float.valueOf(f2), Float.valueOf(f3), Float.valueOf(cachedValues[3])));
            }
        }
    }
}
