package com.zhenwei.test.thread;

import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * @ClassName ThreadPool
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/10 9:54
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ThreadPool {

    private static ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(5,10,5, TimeUnit.SECONDS ,new LinkedBlockingDeque<>());
    private static int i = 0;

    public static void main(String[] args) {

        threadPoolExecutor.execute(new Runnable() {
            @Override
            public void run() {
                for (int j = 0; j < 100; j++) {
                    System.out.println(i++);
                }
            }
        });
    }





}
