package com.zhenwei.demo.myws.vo;

import java.util.List;

/**
 * @ClassName StudentVO
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/25 13:58
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class StudentVO {

    private int age;

    private String name;

    private String clazz;

    private List<String> parents;

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getClazz() {
        return clazz;
    }

    public void setClazz(String clazz) {
        this.clazz = clazz;
    }

    public List<String> getParents() {
        return parents;
    }

    public void setParents(List<String> parents) {
        this.parents = parents;
    }


    @Override
    public String toString() {
        return "StudentVO{" +
                "age=" + age +
                ", name='" + name + '\'' +
                ", clazz='" + clazz + '\'' +
                ", parents=" + parents +
                '}';
    }
}
