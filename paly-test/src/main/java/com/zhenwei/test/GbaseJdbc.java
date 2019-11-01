package com.zhenwei.test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * @ClassName GbaseJdbc
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/4/22 18:09
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class GbaseJdbc {

    public static void main(String[] args) {
        try {
            Class.forName("com.gbasedbt.jdbc.IfxDriver");
            String url = "jdbc:gbasedbt-sqli://192.168.214.51:6318/db_pki?useUnicode=true&characterEncoding=utf8&autoReconnect=true&failOverReadOnly=false&useSSL=false";
            String username = "gbasedbt";
            String pwd = "gbasedbt";
            Connection connection = DriverManager.getConnection(url, url, pwd);
            String sql = "select * from t_ca";
            PreparedStatement ps = connection.prepareStatement(sql);
            ResultSet rs = ps.executeQuery();
            if(rs != null){
                while (rs.next()){
                    String string = rs.getString("ca");
                }
            }

            rs.close();
            ps.close();
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }finally {

        }


    }


}
