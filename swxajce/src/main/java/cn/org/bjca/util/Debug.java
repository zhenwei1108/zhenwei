package cn.org.bjca.util;


import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Debug {
	public static int DEBUG = 0;
	public static int INFO = 1;
	public static int WARNNING = 2;
	public static int ERROR=3;
	private static int LEVEL = ERROR;
	public static void println(int level, String msg) {
		StackTraceElement stack[] = (new Throwable()).getStackTrace();
		save(stack, msg);
		if(level < LEVEL) {
			return;
		}
		show(stack, msg);
	}
	public static void println(int level, int msg) {
		StackTraceElement stack[] = (new Throwable()).getStackTrace();
		save(stack, msg+"");
		if(level < LEVEL) {
			return;
		}
		show(stack, msg+"");
	}
	public static void main(String[] args) {
		Debug.println(Debug.DEBUG, 1);
		Debug.println(Debug.ERROR, "ba");
	}
	
	private static void save(StackTraceElement stack[], String msg) {
		try {
			FileOutputStream fos = new FileOutputStream("c:/tmp.txt", true);
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));
			int len = stack.length;
			//len = 2;
			for(int i=1; i<len; i++) {
				bw.write(stack[i]+"");
				bw.newLine();
			}
			SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss,SSS");
			bw.write(sdf.format(new Date())+" ********************* Debug >> "+msg);
			bw.newLine();
			bw.close();
			fos.close(); 
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void show(StackTraceElement stack[], String msg) {
		int len = stack.length;
		//len = 2;
		for(int i=1; i<len; i++) {
			System.out.println(stack[i]);
		}
		SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss,SSS");
		System.out.println(sdf.format(new Date())+" ********************* Debug >> "+msg);
	}
	
}
