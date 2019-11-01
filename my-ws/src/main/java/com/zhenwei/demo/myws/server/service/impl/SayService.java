package com.zhenwei.demo.myws.server.service.impl;

import com.zhenwei.demo.myws.server.service.BaseService;
import com.zhenwei.demo.myws.vo.StudentVO;
import org.springframework.stereotype.Service;
import javax.jws.WebService;

/**
 * @ClassName SayService
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/14 10:00
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/
@WebService(name = "sayService",targetNamespace = "http://server.webService.zhenwei.com",endpointInterface = "com.zhenwei.demo.myws.server.service.BaseService")
@Service
public class SayService implements BaseService {


    @Override
    public String saySomething() {
        System.out.println("i will say Something");
        return "hello world";
    }

    @Override
    public void getHello(){
        System.out.println("Hello");
    }

    @Override
    public StudentVO setStudent(StudentVO student) {
        System.out.println("this is students");
        System.out.println(student);
        student.setClazz("哈哈哈哈");
        return student;
    }

}
