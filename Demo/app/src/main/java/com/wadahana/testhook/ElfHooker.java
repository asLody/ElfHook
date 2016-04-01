package com.wadahana.testhook;

import android.util.Log;
/**
 * Created by wuxin on 3/24/16.
 */
public class ElfHooker {
    private static final String TAG = "ElfHooker";
    private static boolean isLoadLibrary;
    public native int setHook();
    public native int test();

    static {
        try {
            System.loadLibrary("ElfHook");
            isLoadLibrary = true;
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Nativie library not found! Please copy libElfHook.so into your project");
            isLoadLibrary = false;
        } catch (Throwable e) {
            isLoadLibrary = false;
            Log.d(TAG, "Failed to load library ElfHook: " + e.getMessage());
        }
    }

}
