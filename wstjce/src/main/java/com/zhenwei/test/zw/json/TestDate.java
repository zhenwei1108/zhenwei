package com.zhenwei.test.zw.json;

import com.alibaba.fastjson.JSON;

import java.util.Date;

/**
 * @ClassName TestDate
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/4 18:19
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class TestDate {


    /**
     * @Author zhangzhenwei
     * @Date 2019/6/4 18:25
     * @Param [args]
     * @return void
     *
     * 1559643913807
     * {"end":1559643913807,"userName":"瓜子"}
     *
     * @Description main
     **/
    public static void main(String[] args) {
        MyDateVO myDateVO = new MyDateVO();
        Date date = new Date();
        System.out.println(date.getTime());
        myDateVO.setEnd(date);
        myDateVO.setUserName("瓜子");
        String json = JSON.toJSONString(myDateVO);
        System.out.println(json);


    }



}
