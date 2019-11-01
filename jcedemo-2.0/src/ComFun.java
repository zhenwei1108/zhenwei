
public class ComFun {
	//打印十六进制
	public static void printfHexString(byte[] data)
	{
		int i = 0, j = 0;
		
		for (i=0; i<data.length; i++)
		{
			String hex = Integer.toHexString(data[i]&0xFF);
			if (hex.length() == 1)
			{
				hex = '0'+hex;
			}
			System.out.printf(hex.toUpperCase()+" ");
			j ++;
			if (j%16 == 0)
			{
				System.out.printf("\n");
			}
		}
		System.out.printf("\n");
	}
}
