package com.zhenwei.test.queue;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * @ClassName ArrayBlockeQueueTest
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/18 16:04
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ArrayBlockeQueueTest {


    public static void main(String[] args) {

        BlockingQueue<String> queue = new ArrayBlockingQueue(10);
        try {
            for (int i = 0; i < 12; i++) {
                System.out.println(i);
                queue.add("haha"+i);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println(queue.size());
    }

}
