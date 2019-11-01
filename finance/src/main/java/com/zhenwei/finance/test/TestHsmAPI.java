package com.zhenwei.finance.test;

/**
 * @ClassName TestHsmAPI
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/5 13:49
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

import com.sansec.sjj1212.HsmApi;
import com.sansec.sjj1212.HsmUtil;
import com.sansec.sjj1212.PrintUtil;
import com.sansec.sjj1212.Results;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class TestHsmAPI
{
    public static void main(String[] args) throws Exception
    {

        test_genkey();

        test_generateRootKey();

        test_deriveKey();

        test_importKey();

        test_generateKey();

        test_exportKey();

        test_encrypt();

        test_decrypt();

        test_generateMac();
    }







    public static void test_genkey() throws Exception {
        HsmApi hsm = new HsmApi();

        byte []out = hsm.generateKey ("S", 22);

        PrintUtil.printWithHex(out);
    }

    public static void test_generateRootKey() throws Exception {
        HsmApi hsm = new HsmApi();

        byte []a = "1234567812345678".getBytes();

        byte[] out  = hsm.generateRootKey (a, 1003, 1004, "000");
        PrintUtil.printWithHex(out);
//		System.out.println(out);
    }

    public static void test_deriveKey() throws Exception {
        HsmApi hsm = new HsmApi();
        String pubkey = "A0IABNk3VZxSOIO07TOOLo/Yn2Z42F7Hbgo7UGFecgzxuZ/LKrjwhF97Efn7q7XL5sJDBT4SJHNotGbswymIHqXYZtQ=";

        byte []publickey = Base64.decode(pubkey);
//		PrintUtil.printWithHex(publickey);
        Results s = hsm.deriveKey(1001, "000", "SM4-ECB", "1234567812345678".getBytes(), 1, publickey,"SM2");


        PrintUtil.printWithHex(s.getDerive());
        PrintUtil.printWithHex(s.getEncrypt_key());

    }

    public static void test_importKey() throws Exception {
        HsmApi hsm = new HsmApi();

        String keyCiphers = "2B8BB935389677956ADC6F7C5B876AFE";
//		String keyCiphers = "C6796BF982368B32FF1A1E28030CDF15";

        byte [] keyCipher = HsmUtil.Txt2Hex(keyCiphers);
//		PrintUtil.printWithHex(keyCipher);

        byte[] a = hsm.importKey(keyCipher, 0,"000", 1, 2001, "S");

        PrintUtil.printWithHex(a);

    }
    public static void test_generateKey() throws Exception {
        HsmApi hsm = new HsmApi();
        String pubkey = "A0IABNk3VZxSOIO07TOOLo/Yn2Z42F7Hbgo7UGFecgzxuZ/LKrjwhF97Efn7q7XL5sJDBT4SJHNotGbswymIHqXYZtQ=";

        byte []publickey = Base64.decode(pubkey);


        byte []a = hsm.generateKey("SM2", publickey, 2001, 1);
        PrintUtil.printWithHex(a);
    }

    public static void test_exportKey() throws Exception {
        HsmApi hsm = new HsmApi();

        byte[] a = hsm.exportKey(1001, "00A", "S", 2001);
        PrintUtil.printWithHex(a);

    }
    public static void test_encrypt() throws Exception {
        HsmApi hsm = new HsmApi();

        byte []data = "1234567812345678".getBytes();
//		PrintUtil.printWithHex(data);
        byte []deriveData = "1234567812345678".getBytes();
        byte []iv = "1234567812345678".getBytes();
        byte [] key = HsmUtil.Txt2Hex("2B8BB935389677956ADC6F7C5B876AFE");
//		PrintUtil.printWithHex(key);

        byte[]a = hsm.encrypt(0, "SM4","CBC", "0", key, data, deriveData, 0, iv);
        PrintUtil.printWithHex(a);

    }

    public static void test_decrypt() throws Exception {
        HsmApi hsm = new HsmApi();

        byte []data = HsmUtil.HexString2Bytes("4A5EB7106486672FE79074965E871925");
//		PrintUtil.printWithHex(data);
        byte []deriveData = "1234567812345678".getBytes();
        byte []iv = "1234567812345678".getBytes();

        byte []a = hsm.decrypt(1001, "SM4", "CBC","0", null, data, deriveData, 0, iv);
//		PrintUtil.printWithHex(a);
        System.out.println(new String(a) );
    }
    public static void test_generateMac() throws Exception {
        HsmApi hsm = new HsmApi();
        byte []iv = "1234567812345678".getBytes();
        byte []data = "1234567812345678".getBytes();
        byte []key = HsmUtil.Txt2Hex("2B8BB935389677956ADC6F7C5B876AFE");
        byte []deriveData = "1234567812345678".getBytes();
//		PrintUtil.printWithHex(deriveData);

        String a = hsm.generateMac("SM4", 1, 0, key, deriveData, 1, iv, data);
        System.out.println(a);
    }

}
