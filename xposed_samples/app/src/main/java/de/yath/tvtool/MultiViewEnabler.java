package de.yath.tvtool;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.media.tv.TvContract;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.KeyEvent;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MultiViewEnabler implements IXposedHookLoadPackage {
    private static final String TAG = "MultiViewEnabler";

    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam.packageName.equals("org.droidtv.playtv")) {
            // Make PlayTvActivity.onKeyDown not ignore the Multiview key.
            XposedHelpers.findAndHookMethod(XposedHelpers.findClass("org.droidtv.playtv.PlayTvActivity", lpparam.classLoader),
                    "onKeyDown", int.class, KeyEvent.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            // PlayTvActivity.onKeyDown checks, for key code 171, whether property 22
                            // ("g_option_code__OPC_HW_DUAL_TUNERS") equals 1 and if so, calls
                            // keyStartActivity("org.droidtv.action.MULTIVIEW", key). The MultiviewDrawerActivity
                            // is registered for this activity.
                            //
                            // Unconditionally invoke keyStartActivity for that key here and return.

                            int key = (int) (param.args[0]);
                            if (key != 171) {
                                Log.d(TAG, "Unknown key code " + key + " ignored");
                                return;
                            }
                            Log.i(TAG, "Key is " + key + ", calling keyStartActivity and returning early");
                            XposedHelpers.callMethod(param.thisObject, "keyStartActivity", "org.droidtv.action.MULTIVIEW", key);
                            param.setResult(true); // return true early.
                        }
                    });

            // Make PlayTVMultiView always register itself.
            Class mvClass = XposedHelpers.findClass("org.droidtv.playtv.PlayTVMultiView", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(mvClass, "evaluateMultiview", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    // PlayTVMultiView is always instantiated from a PlayTvActivity. Its evaluateMultiview()
                    // checks input source, channel being installed, etc. and either registers or unregisters
                    // itself with org.droidtv.settings.multiview.MultiviewService. In case of unregistration,
                    // it also exits MultiView mode if it is active.
                    //
                    // Here, we unconditionally register as being MV-capable.

                    final Object theirs = param.thisObject;
                    Runnable r = new Runnable() {
                        @Override
                        public void run() {
                            Log.d(TAG, "In " + "evaluateMultiview" + "'s Runnable, calling registerMultiview.");
                            XposedHelpers.callMethod(theirs, "registerMultiview");
                        }
                    };
                    Handler handler = (Handler) XposedHelpers.getObjectField(theirs, "mhandler");
                    if (!handler.post(r))
                        throw new IllegalStateException("Can't post " + r + " to " + handler + "!");
                    Log.d(TAG, "Posted Runnable for registering Multiview; returning now.");
                    param.setResult(null); // return early.
                }
            });

            // Tune to correct source after Multiview has been entered.
            XposedHelpers.findAndHookMethod(mvClass, "enterplaytvMultiview", new XC_MethodHook() {
                @TargetApi(21)
                protected void afterHookedMethod(XC_MethodHook.MethodHookParam param) {
                    Object auxView = XposedHelpers.getObjectField(param.thisObject, "auxView");
                    final String INPUT_ID = "com.mediatek.tvinput/.hdmi.HDMIInputService/HW7";
                    //Uri u = TvContract.buildChannelUriForPassthroughInput(INPUT_ID);
                    @SuppressLint("MissingPermission") Uri u = TvContract.buildChannelUri(5134); // ARD analog // XXX??!
                    Log.i(TAG, "after enterplaytvMultiview, tuning to " + u + " on path 1");
                    Bundle b = new Bundle();
                    b.putInt("tunePath", 1);
                    XposedHelpers.callMethod(auxView, "tune", INPUT_ID, u, b);
                    Log.i(TAG, "done tuning.");
                }
            }); // findAndHook enterplaytvMultiview

        } // "org.droidtv.playtv"

        // com.mediatek.tvinput/.hdmi.HDMIInputService/HW7
//        if (lpparam.packageName.equals("org.droidtv.settings")) {
//            Class c = XposedHelpers.findClass("org.droidtv.multiview.MultiviewDrawerActivity", lpparam.classLoader);
//            XposedHelpers.findAndHookMethod(c, "onItemClick", long.class, new XC_MethodHook() {
//                @Override
//                @TargetApi(21)
//                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
//                    Uri u = TvContract.buildChannelUriForPassthroughInput("com.mediatek.tvinput/.hdmi.HDMIInputService/HW7");
//                    Log.i(TAG, "onItemClick: using channel URI = " + u.toString());
//                    Intent i = new Intent("android.intent.action.VIEW", u);
//                    assert (Intent.FLAG_ACTIVITY_NEW_TASK == 268435456);
//                    i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
//                    XposedHelpers.callMethod(param.thisObject, "startActivity", i);
//                    param.setResult(null);
//                }
//            });
//        }
    }

}
