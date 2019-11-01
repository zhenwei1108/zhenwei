package com.zhenwei.all.config.config;

import com.zhenwei.all.config.config.test.BuildConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ConfigApplication {

    public static void main(String[] args) {
        System.setProperty("env","DEV");
        SpringApplication.run(ConfigApplication.class, args);
        BuildConfig.buildMineConfig();
    }

}
