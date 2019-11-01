package com.zhenwei.demo.myws.controller;

import com.zhenwei.demo.myws.server.service.BaseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName BaseConrtoller
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/20 15:27
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/
@RestController
public class BaseConrtoller {

    @Autowired
    private BaseService service;

    @RequestMapping("hello")
    public String getHello(){
        service.getHello();
        return "hello world";
    }


}
