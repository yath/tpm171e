package de.yath.tvtool;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import androidx.annotation.NonNull;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

class RCFirmwareUpdateSilencer implements IXposedHookLoadPackage {
    private static final String TAG = "XposedTVTool";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("org.droidtv.settings"))
            return;

        Class c = XposedHelpers.findClass("org.droidtv.upgradeapp.BTRCUpgradeReminder", lpparam.classLoader);
        // Make onReceive, which would trigger the popup, a no-op.
        XposedHelpers.findAndHookMethod(c, "onReceive", Context.class, Intent.class, XC_MethodReplacement.returnConstant(null));
        Log.i(TAG, "Disabled Bluetooth RC firmware upgrade reminder");
    }
}
