import java.util.Map;

public class test {


    public static void main(String[] args) {

        String path = Thread.currentThread().getContextClassLoader().getResource("").getPath();
        int lastindex = path.lastIndexOf("/");
        String filePath = "";
        String javaPath;
        if (!"".equals(path)) {
            javaPath = path.substring(0, lastindex);
            lastindex = javaPath.lastIndexOf("/");
            javaPath = javaPath.substring(0, lastindex);
            filePath = javaPath + "/conf/hsminfo.properties";
            System.out.println("111:"+filePath);
        }

        javaPath = System.getProperty("java.home");
        System.out.println("java:"+javaPath);


        Map<String, String> map = System.getenv();
        filePath = (String)map.get("HSMAPI_INFO");
        System.out.println("final:"+filePath);


        }




}
