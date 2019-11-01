package com.zhenwei.demo.myws.server.service;

import com.zhenwei.demo.myws.vo.StudentVO;

import javax.jws.WebMethod;
import javax.jws.WebResult;
import javax.jws.WebService;

@WebService
public interface BaseService {

    @WebMethod
    @WebResult
    public String saySomething();


    @WebMethod
    public void getHello();


    @WebMethod
    public StudentVO setStudent(StudentVO student);


}
