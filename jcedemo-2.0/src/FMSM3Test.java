import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import org.apache.log4j.Logger;

import com.fmjce.crypto.util.Util;

import fisher.man.crypto.digests.FMSM3;


/**
 *SM3测试
 */
public class FMSM3Test {
	Logger logger = Logger.getLogger(FMSM3Test.class);
	/**
	 * SM3withSM2测试
	 */
	public void SM3WithSM2Test(){
		byte[] bID = new byte[1];
		FMSM3 sm3 = new FMSM3();
		byte[] Out = null;
		bID[0] = 0;
		
		byte[] indata = new byte[32];
		for(int i=0;i<indata.length;i++){
			indata[i] = (byte)i;
		}
		
		//ID值长度大于0，小于64,自定义
		//若未定义pid值，内部默认为“1234567812345678”
		FMSM2 sm2 = new FMSM2();
		KeyPair kp = sm2.GenerateExternalSM2KeyPair();
		
		PublicKey pubKey = kp.getPublic();		
			
		ECPublicKey ecpubkey = (ECPublicKey)pubKey;
		ECPoint ecpoint = ecpubkey.getW();
		BigInteger x = ecpoint.getAffineX();
		BigInteger y = ecpoint.getAffineY();	
		
		byte[] bx = x.toByteArray();
		byte[] by = y.toByteArray();
		
        byte[] encPubKey = new byte[68];
        
        int bits = 256;
        
        byte[] keysize = Util.intToByteArray(bits);

        System.arraycopy(keysize, 0, encPubKey, 0, 4);
        
        if (bx.length > 32){
        	System.arraycopy(bx, bx.length - 32, encPubKey, 4, 32);
        }else {
           System.arraycopy(bx, 0, encPubKey, 4+(32-bx.length), bx.length);
        } 
            
        if (by.length > 32){
        	System.arraycopy(by, by.length - 32, encPubKey, 36, 32);
        } else {
        	System.arraycopy(by, 0, encPubKey, 36+(32-by.length), by.length);
        }
            
		sm3.SetKeyAndID(encPubKey, "1234567812345678".getBytes(), 16);
		sm3.reset();
		Out = new byte[32];
		sm3.update(indata, 0, indata.length);	
		sm3.doFinal(Out, 0);
//		ComFun.printfHexString(Out);
	
		byte[] sign = sm2.ExternalSM2Sign("SM2", kp.getPrivate(), Out); //"SM3withSM2"
		if(sign == null){
			logger.error("external SM3withSM2 sign error");
			return;
		}else{
			logger.info("external SM3withSM2 sign ok");
		}
//		ComFun.printfHexString(sign);		
		
		boolean rv1 = sm2.ExternalSM2Verify("SM3withSM2", kp.getPublic(), indata, sign);
		if(rv1){
			logger.info("external SM3withSM2 verify ok");
		}else{
			logger.error("external SM3withSM2 verify error");
			return;
		}
	}
}
