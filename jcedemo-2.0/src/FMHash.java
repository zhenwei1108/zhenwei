import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

import fisher.man.util.encoders.Hex;


public class FMHash {
	
	Logger logger = Logger.getLogger(FMSM1.class);
	
	public void hashTest(){
		byte[] inBuf = new byte[256];
		byte[] result = null;
		for(int i = 0; i < inBuf.length; i++)
		{
			inBuf[i] = (byte)i;
		}
		try {
			MessageDigest dig = MessageDigest.getInstance("SHA1","FishermanJCE");
			dig.reset();
			dig.update(inBuf);
			result = dig.digest();
		} catch (Exception e) {
		   e.printStackTrace();
		   logger.error("hash is error!");
		}
		ComFun.printfHexString(result);
	}
	
	/**
	 * HMAC
	 */
	public void HMACTest(){
        byte[]   keyBytes = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] input = Hex.decode("12345678");
        try {
			SecretKey skey = new SecretKeySpec(keyBytes, "HMac/SHA1");
			Mac mac = Mac.getInstance("HMac/SHA256", "FishermanJCE");
			mac.init(skey);
			mac.reset();
			mac.update(input, 0, input.length);
			byte[] out = new byte[128];
			out = mac.doFinal();
			ComFun.printfHexString(out);
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
	
	/**
	 * CMAC
	 */
	public void CMACTest(){
		byte[] keyBytes128 = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
		byte[] input = Hex.decode("12345678");
	    try {
			Mac mac = Mac.getInstance("AESCMAC", "FishermanJCE");
			//128字节key
			SecretKeySpec key = new SecretKeySpec(keyBytes128, "SM1");
			mac.init(key);
			mac.update(input, 0, input.length);
			byte[] out = new byte[mac.getMacLength()];
			mac.doFinal(out, 0);
			ComFun.printfHexString(out);
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}
