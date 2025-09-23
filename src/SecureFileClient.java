
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import javax.net.ssl.*;

/** A client-side class that uses a secure Tcp/IP socket
  */
public class SecureFileClient {
	
	private InetAddress host;
	private int port;
	// This is not a reserved port number
	static final int DEFAULT_PORT = 8189;
	static final String KEYSTORE = "certs/client_keystore.ks";
	static final String TRUSTSTORE = "certs/client_trustore.ks";
	static final String KEYSTOREPASS = "clientks";
	static final String TRUSTSTOREPASS = "clientts"; //clients

	/** Constructor
	  * @param host Internet address of the host where the server is located
	  * @param port Port nurnber on the host where the server is listening
	  */
	public SecureFileClient(InetAddress host, int port) {
		this.host = host;
		this. port = port;
	}
	
	/** The method used to start a client object
	  */
	public void run() {
		try {
			
			KeyStore ks = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(KEYSTORE), KEYSTOREPASS.toCharArray());

			KeyStore ts = KeyStore.getInstance("JCEKS");
			ts.load(new FileInputStream(TRUSTSTORE), TRUSTSTOREPASS.toCharArray());

			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, KEYSTOREPASS.toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ts);
			
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			SSLSocketFactory sslFact = sslContext.getSocketFactory();
			SSLSocket client = (SSLSocket) sslFact.createSocket(host, port);
			client.setEnabledCipherSuites(client.getSupportedCipherSuites());
			
			BufferedReader socketIn = new BufferedReader(new InputStreamReader(client.getInputStream()));
			PrintWriter socketOut = new PrintWriter(client.getOutputStream(), true);
			
			String nurnbers = "1.2 3.4 5.6";
			System.out.println("Adding the nurnbers " + nurnbers + " together securely");
			
			socketOut.println(nurnbers);
			System.out.println(socketIn.readLine());
			socketOut.println("");
			
		} catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
	}
	
	/** The test method for the class
	  * @param args[0] Optional port number and host name
	  */
	public static void main( String[] args) {
		
		try {
            InetAddress host = InetAddress.getLocalHost();
            int port = DEFAULT_PORT;
            if (args.length > 0) {
                port = Integer.parseInt(args[0]);
            }
            if (args.length > 1) {
                host = InetAddress.getByName(args[1]);
            }
            SecureFileClient addClient = new SecureFileClient(host, port);
            addClient.run();
            
        } catch (UnknownHostException uhx) {
            System.out.println(uhx);
            uhx.printStackTrace();
        }

	}
	
		
}
