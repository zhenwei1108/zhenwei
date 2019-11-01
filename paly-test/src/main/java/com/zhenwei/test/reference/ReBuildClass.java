package com.zhenwei.test.reference;

import com.zhenwei.test.vo.User;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * @ClassName ReBuildClass
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/20 10:27
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ReBuildClass {


    public static void main(String[] args) {
        User user = new User("张三",11);
        String build = build(user);
        System.out.println(build);

    }



    public static String build(Object obj){
        try {
            Class<?> clazz = obj.getClass();
            Field[] declaredFields = clazz.getDeclaredFields();
            for (Field field : declaredFields) {
                field.setAccessible(true);
                String name = field.getName();//字段属性名
                Class<?> paramType = field.getType();//字段类型
                String getMethod = "get"+name.substring(0,1).toUpperCase()+name.substring(1);
                System.out.println("方法是:"+getMethod+"  ,字段类型是:"+paramType);
                Method method = clazz.getDeclaredMethod(getMethod);
                Object invoke = method.invoke(obj);
                System.out.println(invoke);


            }
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
        return null;
    }



}
