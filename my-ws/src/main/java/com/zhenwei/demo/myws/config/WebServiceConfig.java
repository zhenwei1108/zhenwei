package com.zhenwei.demo.myws.config;

import com.zhenwei.demo.myws.server.service.impl.SayService;
import org.apache.cxf.Bus;
import org.apache.cxf.bus.spring.SpringBus;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.transport.servlet.CXFServlet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;

import javax.xml.ws.Endpoint;

/**
 * @ClassName WebServiceConfig
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/14 10:06
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/
@Configuration
public class WebServiceConfig {

    @Autowired
    private SayService sayService;

    /**
     * springboot默认注册的是 dispatcherServlet，
     * 当手动配置 ServletRegistrationBean后springboot不会再去注册默认的dispatcherServlet，
     * 所以需要我们在启动类里手动去注册一个dispatcherServlet
     */

    //http请求可以使用
    @Bean
    public ServletRegistrationBean dispatcherServlet() {
        //注解扫描上下文
        AnnotationConfigWebApplicationContext applicationContext = new AnnotationConfigWebApplicationContext();
        //项目包名
        applicationContext.scan("com.zhenwei.demo.myws");
        DispatcherServlet rest_dispatcherServlet = new DispatcherServlet(applicationContext);
        ServletRegistrationBean registrationBean = new ServletRegistrationBean(rest_dispatcherServlet);
        registrationBean.setLoadOnStartup(1);
        registrationBean.addUrlMappings("/*");
        return registrationBean;
    }

    //webservice
    @Bean
    public ServletRegistrationBean dispatServlet() {
        return new ServletRegistrationBean(new CXFServlet(), "/webService/*");
    }


    @Bean(name = Bus.DEFAULT_BUS_ID)
    public SpringBus springBus() {
        return new SpringBus();
    }

    @Bean(name = "WebServiceDemoEndpoint")
    public Endpoint endpoint(){
        EndpointImpl endpoint = new EndpointImpl(springBus(),sayService);
        endpoint.publish("/Say");
        return endpoint;
    }


}
