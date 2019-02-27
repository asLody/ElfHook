package com.wadahana.testhook;

import android.content.Intent;
import android.os.Bundle;
import android.os.HandlerThread;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import java.util.logging.Handler;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private Button mButton1;
    private Button mButton2;
    private Button mButton3;
    private Button mButton4;

    private ElfHooker mElfHooker;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mButton1 = (Button)this.findViewById(R.id.button1);
        mButton2 = (Button)this.findViewById(R.id.button2);
        mButton3 = (Button)this.findViewById(R.id.button3);
        mButton4 = (Button)this.findViewById(R.id.button4);

        mButton1.setOnClickListener(this);
        mButton2.setOnClickListener(this);
        mButton3.setOnClickListener(this);
        mButton4.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if(v == (View)mButton1) {
            System.out.printf("HttpClient 按钮\n");
            new Thread(new Runnable(){
                public void run() {
                    HttpClientTest client = new HttpClientTest();
                    client.get("http://www.sina.com");
                }
            }).start();
        } else if (v == (View)mButton2) {
            System.out.printf("Vitamio 按钮\n");
        } else if (v == (View)mButton3) {
            System.out.printf("Webview 按钮\n");
            Intent intent = new Intent();
            intent.setClass(MainActivity.this, WebActivity.class);
            startActivity(intent);
        } else if (v == (View)mButton4) {
            System.out.printf("Hook 按钮\n");
            mElfHooker = new ElfHooker();
            mElfHooker.setHook();
            mElfHooker.test();
        }
    }
}
