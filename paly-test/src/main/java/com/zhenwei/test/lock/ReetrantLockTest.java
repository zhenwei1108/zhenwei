package com.zhenwei.test.lock;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @ClassName ReetrantLockTest
 * @Description
 * @Date 2019/8/31 18:46
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ReetrantLockTest {

  public static void main(String[] args) {

    ReentrantLock lock = new ReentrantLock();

    if (!lock.isLocked()){
      try {
        lock.lock();
        boolean b = lock.tryLock();
        boolean tryLock = lock.tryLock(1000, TimeUnit.MINUTES);




      } catch (InterruptedException e) {
        e.printStackTrace();
      } finally {
        lock.unlock();
      }



    }


  }




}
