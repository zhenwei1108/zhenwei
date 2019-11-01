package com.zhenwei.demo.keypool.util;

import cn.com.westone.bouncycastle.jce.provider.WestoneProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @ClassName EncDecUtil
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/8 19:55
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class EncDecUtil {


    public static byte[] encDecBySM4(Key key, byte[] source) {
        try {
            Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5PADDING", WestoneProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(source);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;

    }


}
