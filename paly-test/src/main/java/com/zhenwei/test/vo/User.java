package com.zhenwei.test.vo;

import java.util.List;

/**
 * @ClassName User
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/20 10:28
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class User {

    private String name;

    private int age;

    private List<String> like;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public List<String> getLike() {
        return like;
    }

    public void setLike(List<String> like) {
        this.like = like;
    }

    public User(String name, int age, List<String> like) {
        this.name = name;
        this.age = age;
        this.like = like;
    }

    public User() {
    }

    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }

    @Override
    public String toString() {
        return "User{" +
                "name='" + name + '\'' +
                ", age=" + age +
                ", like=" + like +
                '}';
    }
}
