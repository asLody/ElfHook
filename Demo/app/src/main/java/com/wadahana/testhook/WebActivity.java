package com.wadahana.testhook;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.KeyEvent;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;

/**
 * Created by wuxin on 3/10/16.
 */
public class WebActivity extends AppCompatActivity implements View.OnClickListener  {
    private Button  mLoadButton;
    private Button  mGobackButton;
    private Button  mGoforwardButton;
    private Button  mHookButton;
    private WebView mWebView;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web);

        mLoadButton         = (Button)this.findViewById(R.id.button_load);
        mGobackButton       = (Button)this.findViewById(R.id.button_goback);
        mGoforwardButton    = (Button)this.findViewById(R.id.button_goforward);
        mHookButton         = (Button)this.findViewById(R.id.button_hook);

        mWebView            = (WebView) findViewById(R.id.webView);

        mLoadButton.setOnClickListener(this);
        mGobackButton.setOnClickListener(this);
        mGoforwardButton.setOnClickListener(this);
        mHookButton.setOnClickListener(this);

        WebSettings settings = mWebView.getSettings();
        settings.setSupportZoom(true);          //支持缩放
        settings.setBuiltInZoomControls(true);  //启用内置缩放装置
        settings.setJavaScriptEnabled(true);    //启用JS脚本

        mWebView.setWebViewClient(new WebViewClient() {
            //当点击链接时,希望覆盖而不是打开新窗口
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                view.loadUrl(url);  //加载新的url
                return true;    //返回true,代表事件已处理,事件流到此终止
            }
        });

        //点击后退按钮,让WebView后退一页(也可以覆写Activity的onKeyDown方法)
        mWebView.setOnKeyListener(new View.OnKeyListener() {
            @Override
            public boolean onKey(View v, int keyCode, KeyEvent event) {
                if (event.getAction() == KeyEvent.ACTION_DOWN) {
                    if (keyCode == KeyEvent.KEYCODE_BACK && mWebView.canGoBack()) {
                        mWebView.goBack();   //后退
                        return true;    //已处理
                    }
                }
                return false;
            }
        });

        mWebView.setWebChromeClient(new WebChromeClient() {
            //当WebView进度改变时更新窗口进度
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                //Activity的进度范围在0到10000之间,所以这里要乘以100
                // LoadActivity.this.setProgress(newProgress * 100);
            }
        });

        mLoadButton.performClick();
    }

    @Override
    public void onClick(View v) {
        if(v == (View)mLoadButton) {
            System.out.printf("加载 按钮\n");
            mWebView.loadUrl("http://www.baidu.com");
            mWebView.requestFocus();
        } else if (v == (View)mGobackButton) {
            System.out.printf("后退 按钮\n");
            mWebView.goBack();
        } else if (v == (View)mGoforwardButton) {
            System.out.printf("前进 按钮\n");
            mWebView.goForward();
        } else if (v == (View)mHookButton) {
            ElfHooker hooker = new ElfHooker();
            hooker.setHook();
        }
    }
}

/*
 Hook Module : /system/app/webview/lib/arm64/libwebviewchromium.so
05-05 18:36:13.232 6278-6278/com.wadahana.testhook I/ELFKooH: [+] sym 0x7f641beaa0, symidx 613.
*/