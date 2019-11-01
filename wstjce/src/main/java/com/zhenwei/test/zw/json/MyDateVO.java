package com.zhenwei.test.zw.json;

import java.util.Date;

/**
 * @ClassName MyDateVO
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/4 18:19
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class MyDateVO {


    private Date start;

    private Date end;

    private String userName;


    public Date getStart() {
        return start;
    }

    public void setStart(Date start) {
        this.start = start;
    }

    public Date getEnd() {
        return end;
    }

    public void setEnd(Date end) {
        this.end = end;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    @Override
    public String toString() {
        return "MyDateVO{" +
                "start=" + start +
                ", end=" + end +
                ", userName='" + userName + '\'' +
                '}';
    }
}
