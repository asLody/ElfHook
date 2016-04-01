package com.wadahana.testhook;

import android.app.Application;

import com.tm.sdk.proxy.Proxy;

/**
 * Created by wuxin on 3/9/16.
 */
public class HookTestApplication extends Application {

    ElfHooker mElfHooker;
    @Override
    public void onCreate()
    {
//        Proxy. supportWebview(this);
//        Proxy.start(this, "");
//        mElfHooker = new ElfHooker();
//        mElfHooker.test();
        super.onCreate();
    }

}
