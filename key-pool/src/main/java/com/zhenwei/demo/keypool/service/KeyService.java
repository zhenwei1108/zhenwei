package com.zhenwei.demo.keypool.service;

import com.zhenwei.demo.keypool.util.EncDecUtil;
import com.zhenwei.demo.keypool.util.KeyUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Base64;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * @ClassName KeyService
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/8 19:41
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/
@Component
public class KeyService {

    private final static Logger logger = LoggerFactory.getLogger(KeyService.class);

    private static final int KEY_POOL_SIZE = 500;

    private static final BlockingQueue queue = new ArrayBlockingQueue(KEY_POOL_SIZE);

    private static final ThreadPoolExecutor executor = new ThreadPoolExecutor(100, 500, 5, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>());

    @PostConstruct
    public static void init() {

        Runnable keyPool = () -> {
            while (true) {
                if(queue.size() < KEY_POOL_SIZE) {
                    putKeyToPool();
                }
            }
        };
        executor.execute(keyPool);
    }


    public static void putKeyToPool() {
        try {
            logger.error("当前队列中数量为:{}", queue.size());
            KeyPair keyPair = KeyUtil.genSM2KeyPair();
            logger.error("产生非对称密钥SM2:{}", keyPair);
            SecretKey secretKey = KeyUtil.genSM4KeyByIndex(2);
            logger.error("产生对称密钥SM4:{}", keyPair);
            if(keyPair == null || secretKey == null) throw new RuntimeException("产生密钥失败");
            byte[] encData = EncDecUtil.encDecBySM4(secretKey, keyPair.getPrivate().getEncoded());
            logger.error("加密SM2密钥为:{}", encData);
            String data = Base64.getEncoder().encodeToString(encData);
            System.out.println("加密后密钥为:" + data);
            queue.put(data);
        } catch (Exception e) {
            System.out.println("错误信息: " + e);
            e.printStackTrace();
        }
    }

}
