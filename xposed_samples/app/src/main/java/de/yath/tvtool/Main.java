package de.yath.tvtool;

import android.annotation.TargetApi;
import android.util.Log;

import de.robv.android.xposed.IXposedHookInitPackageResources;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_InitPackageResources;
import de.robv.android.xposed.callbacks.XC_LoadPackage;


public class Main implements IXposedHookLoadPackage, IXposedHookZygoteInit, IXposedHookInitPackageResources {
    private static final String TAG = "XposedTVTool";

    private static final LogoPatcher lp = new LogoPatcher();
    private static final IXposedHookLoadPackage loadPackageHooks[] = new IXposedHookLoadPackage[]{
            new RCFirmwareUpdateSilencer(),
            new MultiViewEnabler(),
            lp,
    };

    private static final IXposedHookZygoteInit zygoteInitHooks[] = new IXposedHookZygoteInit[]{
            lp,
    };
    private static final IXposedHookInitPackageResources initPackageResourcesHooks[] = new IXposedHookInitPackageResources[]{
            lp,
    };

    @Override
    @TargetApi(17)
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        for (IXposedHookLoadPackage hook : loadPackageHooks) {
            try {
                hook.handleLoadPackage(lpparam);
            } catch (Throwable t) {
                Log.e(TAG, "Unable to load " + hook + ": " + t, t);
            }
        }

        if (lpparam.packageName.equals("android")) {
            Class pkgClass = XposedHelpers.findClass("android.content.pm.PackageParser$Package", lpparam.classLoader);

            // https://android.googlesource.com/platform/frameworks/base/+/818d032/services/core/java/com/android/server/pm/PackageManagerService.java#10744
            XposedHelpers.findAndHookMethod("com.android.server.pm.PackageManagerService", lpparam.classLoader,
                    "applyPolicy", pkgClass /* 0: pkg */, int.class /* 1: policyFlags */,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            // https://android.googlesource.com/platform/frameworks/base/+/818d032/core/java/android/content/pm/PackageParser.java#5671
                            Object pkg = param.args[0];
                            String pkgName = (String)XposedHelpers.getObjectField(pkg, "packageName");
                            if (!pkgName.equals("de.yath.tvtest")) {
                                return;
                            }

                            Object appInfo = XposedHelpers.getObjectField(pkg, "applicationInfo");
                            // https://android.googlesource.com/platform/frameworks/base/+/818d032/core/java/android/content/pm/ApplicationInfo.java
                            int oldFlags = XposedHelpers.getIntField(appInfo, "flags");
                            int oldPrivFlags = XposedHelpers.getIntField(appInfo, "privateFlags");
                            int newFlags = oldFlags | 1<<0 /* FLAG_SYSTEM */;
                            int newPrivFlags = oldPrivFlags | 1<<3 /* PRIVATE_FLAG_PRIVILEGED */;
                            XposedBridge.log(String.format("Setting flags 0x%08x -> 0x%08x, private flags 0x%08x -> %08xx for pkg = %s before invocation",
                                    oldFlags, newFlags,
                                    oldPrivFlags, newPrivFlags,
                                    pkgName));
                            XposedHelpers.setIntField(appInfo, "flags", newFlags);
                            XposedHelpers.setIntField(appInfo, "privateFlags", newPrivFlags);
                        }
                    });
        }
    }

    @Override
    public void handleInitPackageResources(XC_InitPackageResources.InitPackageResourcesParam resparam) throws Throwable {
        for (IXposedHookInitPackageResources hook : initPackageResourcesHooks) {
            try {
                hook.handleInitPackageResources(resparam);
            } catch (Throwable t) {
                Log.e(TAG, "Unable to load " + hook + ": " + t, t);
            }
        }
    }

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        for (IXposedHookZygoteInit hook : zygoteInitHooks) {
            try {
                hook.initZygote(startupParam);
            } catch (Throwable t) {
                Log.e(TAG, "Unable to load " + hook + ": " + t, t);
            }
        }
    }
}
