
import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.util.StringTokenizer;

/** An example class that uses the secure server socket class
  */
public class SecureFileServer {
	
	private int port;
	// This is not a reserved port number
	static final int DEFAULT_PORT = 8189;
	static final String KEYSTORE = "certs/server_keystore.ks";
	static final String TRUSTSTORE = "certs/server_trustore.ks";
	static final String KEYSTOREPASS = "serverks";
	static final String TRUSTSTOREPASS = "serverts";
	
	/** Constructor
	  * @param port The port where the server
	  * will listen for requests
	  */
	SecureFileServer( int port ) {
		this. port = port;
	}
	
	/** The method that does the work for the class */
	public void run() {
		try {
			KeyStore ks = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(KEYSTORE), KEYSTOREPASS.toCharArray());
			
			KeyStore ts = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(TRUSTSTORE), TRUSTSTOREPASS.toCharArray());
			
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, KEYSTOREPASS.toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ts);
			
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			SSLServerSocketFactory sslServerFactory = sslContext.getServerSocketFactory();
			SSLServerSocket sss = (SSLServerSocket) sslServerFactory.createServerSocket(port);
			sss.setEnabledCipherSuites(sss.getSupportedCipherSuites());
			SSLSocket incoming = (SSLSocket) sss.accept();
			
			BufferedReader in = new BufferedReader(new InputStreamReader(incoming.getInputStream()));
            PrintWriter out = new PrintWriter(incoming.getOutputStream(), true);
            
            String str;
            
            while ( !(str = in.readLine()).equals("")) {
            	double result = 0;
            	StringTokenizer st = new StringTokenizer(str);
            	try {
	            	while(st.hasMoreTokens()) {
	            		Double d = new Double(st.nextToken());
	            		result += d.doubleValue();
	            	}
	            	out.println("The result is " + result);
            	}
            	catch(NumberFormatException nfe) {
            		out.println("Sorry, your list " + "contains an " + "invalid number");

            	}
        	}
        	incoming.close();

			
		} catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
	
	}
	
	/** The test method for the class
	  * @param args[0] Optional port number in place of the default
	  */
	public static void main( String[] args) {
		int port = DEFAULT_PORT;
		if (args.length > 0) {
			port = Integer.parseInt(args[0]);
		}
		SecureFileServer addServe = new SecureFileServer(port);
		addServe.run();

	}
	
}
