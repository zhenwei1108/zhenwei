package com.zhenwei.all.config.config.test;

import cn.bjca.typhon.client.api.TyphonClient;
import cn.bjca.typhon.client.api.conffile.PropertiesConfFile;
import com.ctrip.framework.apollo.Config;
import com.ctrip.framework.apollo.ConfigService;

import java.util.Properties;
import java.util.Set;

/**
 * @ClassName BuildConfig
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/8 17:36
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class BuildConfig {

    public static void buildMineConfig(){

        Config config = ConfigService.getAppConfig();
        Set<String> propertyNames = config.getPropertyNames();
        for (String propertyName : propertyNames) {
            System.out.println(propertyName);
        }
    }

    public static void genMineConf(){

        PropertiesConfFile application = TyphonClient.getInstance().getProperties("application");
        Properties properties = application.getProperties();
        Object o = properties.getProperty("bjca.ca.jdbc.username");
        System.out.println(o);
    }



    public static void main(String[] args) {
        genMineConf();
    }


}
