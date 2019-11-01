package com.zhenwei.demo.keypool;

import cn.com.westone.bouncycastle.jce.provider.WestoneProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class KeyPoolApplication {

    public static void main(String[] args) {
        Security.addProvider(new WestoneProvider());
        SpringApplication.run(KeyPoolApplication.class, args);
    }

}
