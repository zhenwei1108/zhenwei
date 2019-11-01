package com.zhenwei.demo.http.conf;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @ClassName HttpConnector
 * @Description
 * @Date 2019/11/1 15:06
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/
@Configuration
public class HttpConnector {

  @Bean
  public Connector getConn(){
    Connector connector = new Connector();
    connector.setScheme("http");
    connector.setPort(80);
    connector.setSecure(false);
    connector.setRedirectPort(443);
    return connector;
  }


  @Bean
  public TomcatServletWebServerFactory tomcatServletWebServerFactor(Connector connector){
    TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory(){
      @Override
      protected void postProcessContext(Context context) {
        SecurityConstraint securityConstraint=new SecurityConstraint();
        securityConstraint.setUserConstraint("CONFIDENTIAL");//NONE 关闭SSL
        SecurityCollection collection=new SecurityCollection();
        collection.addPattern("/*");//所有应用都是https
        securityConstraint.addCollection(collection);
        context.addConstraint(securityConstraint);
      }
    };
    tomcat.addAdditionalTomcatConnectors(connector);
    return tomcat;

  }



}
