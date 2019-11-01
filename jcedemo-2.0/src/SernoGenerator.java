
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Random;


public class SernoGenerator{

	private String algorithm = "SHA1PRNG";

	private int noOctets = 8;

	private SecureRandom random;

	private static SernoGenerator instance = null;

	private BigInteger lowest = new BigInteger("0080000000000000", 16);
	private BigInteger highest = new BigInteger("7FFFFFFFFFFFFFFF", 16);

	/**
	 * 使用 SecureRandom 产生证书序列号
	 */
	protected SernoGenerator() throws NoSuchAlgorithmException {
		init();
	}

	private void init() throws NoSuchAlgorithmException {
		random = SecureRandom.getInstance(algorithm);

		long seed = Math.abs((new Date().getTime()) + this.hashCode());
		random.setSeed(seed);
	}

	public static synchronized SernoGenerator instance() throws NoSuchAlgorithmException {
		if (instance == null) {
			instance = new SernoGenerator();
		}
		return instance;
	}

	
	public synchronized BigInteger getSerno() {
		if (noOctets == 0) {
			Random rand = new Random();
			return new java.math.BigInteger(Long.toString(rand.nextInt(4)));
		}
		
		byte[] sernobytes = new byte[noOctets];
		boolean ok = false;
		BigInteger serno = null;
		while (!ok) {
			random.nextBytes(sernobytes);
			serno = (new java.math.BigInteger(sernobytes)).abs();
			// Must be within the range 0080000000000000 - 7FFFFFFFFFFFFFFF
			if ((serno.compareTo(lowest) >= 0)
					&& (serno.compareTo(highest) <= 0)) {
				ok = true;
			} else {
			}
		}
		return serno;
	}

	public int getNoSernoBytes() {
		return noOctets;
	}

	
	public void setSeed(long seed) {
		random.setSeed(seed);
	}

	
	public void setAlgorithm(String algo) throws NoSuchAlgorithmException {
		this.algorithm = algo;
		init();
	}

	
	public void setSernoOctetSize(int noOctets) {
		if (noOctets == 4) {
			lowest = new BigInteger("00800000", 16);
			highest = new BigInteger("7FFFFFFF", 16);
		}
		if ((noOctets != 4) && (noOctets != 8) && (noOctets != 0)) {
			throw new IllegalArgumentException(
					"SernoOctetSize must be 4 or 8 for this generator.");
		}
		this.noOctets = noOctets;
	}

}
