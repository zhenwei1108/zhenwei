package com.zhenwei.test.date;

import static java.time.temporal.ChronoField.PROLEPTIC_MONTH;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * @ClassName TestDate
 * @Description
 * @Date 2019/9/17 15:27
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class TestDate {


  public static void main(String[] args) {

    LocalDate now = LocalDate.now();
    long l1 = now.getLong(PROLEPTIC_MONTH);
    System.out.println(l1);
    System.out.println(now);
    LocalDateTime localDateTime = now.atStartOfDay();
    System.out.println(localDateTime);


  }




}
