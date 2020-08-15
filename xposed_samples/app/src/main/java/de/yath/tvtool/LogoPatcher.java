package de.yath.tvtool;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;
import android.util.Log;

import java.io.ByteArrayOutputStream;

import android.content.res.XModuleResources;
import de.robv.android.xposed.IXposedHookInitPackageResources;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_InitPackageResources.InitPackageResourcesParam;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class LogoPatcher implements IXposedHookZygoteInit, IXposedHookInitPackageResources, IXposedHookLoadPackage {
    private static final String TAG = "XposedTVLogoPatcher";
    private static final String RES_PKG = "org.droidtv.tvsystemui";
    private static final int RES_ORIG = 2130837518;
    private static String MODULE_PATH = null;

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        MODULE_PATH = startupParam.modulePath;
        Log.d(TAG, "Will load replacement logo from "+MODULE_PATH);
    }

    @Override
    public void handleInitPackageResources(InitPackageResourcesParam resparam) throws Throwable {
        if (!resparam.packageName.equals(RES_PKG))
            return;

        Log.i(TAG, "Replacing startup_philips_logo in "+resparam.packageName+" with ours.");
        XModuleResources modRes = XModuleResources.createInstance(MODULE_PATH, resparam.res);
        resparam.res.setReplacement(RES_ORIG, modRes.fwd(R.drawable.startup_philips_logo_yath));
    }


    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals(RES_PKG))
            return;

        // https://github.com/rovo89/XposedBridge/issues/65, except that our caller makes use of the
        // BitmapFactory.Options and ignoring them causes size calculations to fail.

        Log.i(TAG, "Patching decodeResource(Resources, int, BitmapFactory.Options)");
        XposedHelpers.findAndHookMethod(BitmapFactory.class, "decodeResource", Resources.class, int.class, BitmapFactory.Options.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                int id = (int)param.args[1];
                if(id == RES_ORIG) {
                    Resources res = (Resources)param.args[0];
                    BitmapFactory.Options options = (BitmapFactory.Options)param.args[2];

                    Bitmap b = ((BitmapDrawable)res.getDrawable(id)).getBitmap();

                    // We could return b now, except that we’d ignore the options. Therefore, marshal
                    // the Bitmap to a PNG byte[] and use BitmapFactory.decodeByteArray() with our
                    // caller’s options on this PNG.

                    ByteArrayOutputStream s = new ByteArrayOutputStream();
                    b.compress(Bitmap.CompressFormat.PNG, 100, s);
                    byte[] png = s.toByteArray();

                    Bitmap ret = BitmapFactory.decodeByteArray(png, 0, png.length, options);
                    Log.i(TAG, "decodeResource called for RES_ORIG, returning decodeByteArray(byte["+png.length+"], "+options);
                    param.setResult(ret);
                }
            }
        });
    }
}