package de.yath.tvtool;

import android.content.Context;
import android.content.Intent;
import android.os.UserHandle;
import android.util.Log;
import android.view.KeyEvent;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

class GlobalKeyOverrider implements IXposedHookLoadPackage {
    private static final String TAG = "XposedTVKeyOverrider";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("org.droidtv.GlobalKey"))
            return;

        Class c = XposedHelpers.findClass("org.droidtv.GlobalKey.GlobalKeyReceiver", lpparam.classLoader);
        XposedHelpers.findAndHookMethod(c, "handleNonIntKeyAction", Context.class, Intent.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                Context paramContext = (Context)param.args[0];
                Intent paramIntent = (Intent)param.args[1];
                KeyEvent keyEvent = (KeyEvent)paramIntent.getParcelableExtra("android.intent.extra.KEY_EVENT");
                int keyCode = keyEvent.getKeyCode();
                if (keyCode != 375)
                    return;

                Log.i(TAG, "Overriding Netflix key");
                param.setResult(null);
                Intent i = new Intent();
                i.setAction(Intent.ACTION_MAIN);
                i.setClassName("com.google.android.youtube.tv", "com.google.android.apps.youtube.tv.activity.ShellActivity");
                paramContext.startActivity(i);
            }
        });
    }
}
