package com.example.rsa_rc4_p2p;

import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    TextView ServerIP;
    private TextView peerReply, sharedkey;
    private EditText editKeysize,editPeerIP;
    private Button buttonSend;
    private int CLIENT_PORT = 17777;
    private int SERVER_PORT = 18888;
    private int RTSP_server_port = 16666;
    private Socket RTSPsocket;
    private BufferedWriter RTSPBufferedWriterS;
    private BufferedReader RTSPBufferedReader;
    private String CRLF = "\r\n";
    private InetAddress PeerIP;
    private AlgorithmParameterGenerator paramGen;
    private Socket socketAccept;
    private ServerSocket serverSocket;
    private Socket RTSP_server_socket;
    private InetAddress IPAddressClient;
    public static final int RTSPPORT = 16666;
    private int LEN_Key = 10;
    private ArrayAdapter<String> mConversationArrayAdapter;
    private ListView mConversationView;
    static PublicKey Client_RSAPublicKey;
    private String RequestLine;
    private Button startButton;
    private EditText inputMessage;
    private InetAddress PeerIP2;
    private InetAddress PeerIP1;
    private boolean Callee = false;
    private TextView receive_message;
    private int SEND_PORT = 7777;
    private int RECV_PORT = 8888;
    private String MessageInput;
    private DatagramSocket send_socket;
    private String B_shared_key;
    private String B_shared_key2;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        editPeerIP = (EditText)findViewById(R.id.editPeerIP);
        //editKeysize = (EditText)findViewById(R.id.editKeysize);
        buttonSend = (Button)findViewById(R.id.Send_Button);
        peerReply = (TextView)findViewById(R.id.Peer_Reply);
        sharedkey = (TextView)findViewById(R.id.Shared_Key);
        buttonSend.setOnClickListener(startSend);
        ServerIP = (TextView) findViewById(R.id.ServerIP);
        mConversationArrayAdapter = new ArrayAdapter<String>(this, R.layout.list);
        mConversationView = (ListView) findViewById(R.id.ListView);
        mConversationView.setAdapter(mConversationArrayAdapter);
        ServerIP.setText(getIpAddress());
        startButton = (Button) findViewById (R.id.Start_Button);
        inputMessage = (EditText) findViewById (R.id.input_message);
        receive_message = (TextView) findViewById (R.id.receive_message);
        mConversationArrayAdapter = new ArrayAdapter<String>(this, R.layout.message);
        mConversationView = (ListView) findViewById(R.id.ListView);
        mConversationView.setAdapter(mConversationArrayAdapter);
        startButton.setOnClickListener(startP2PSend);
        Thread socketServerThread = new Thread(new socketServerThread());
        socketServerThread.start();
        Thread startReceiveThread = new Thread(new StartReceiveThread());
        startReceiveThread.start();
        try {
            send_socket = new DatagramSocket(SEND_PORT);
        } catch (SocketException e) {
            Log.e("VR", "Sender SocketException");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    private final View.OnClickListener startP2PSend = new View.OnClickListener() {
        @Override
        public void onClick(View arg0) {
            Log.d("VR", "Click OK");
            startP2PSending();
        }
    };
    private final View.OnClickListener startSend = new View.OnClickListener() {
        @Override
        public void onClick(View arg0) {
            Log.d("VR", "Click OK");
            startDH_Client();
        }
    };
    public void   startDH_Client() {
        Thread startClientThread = new Thread (new Runnable() {
            @Override
            public void run() {
                try {
                    PeerIP = InetAddress.getByName(editPeerIP.getText().toString());
                    Log.d("VR", "server IP obtained");
                    RTSPsocket = new Socket(PeerIP, RTSP_server_port);
                    RTSPBufferedWriterS = new BufferedWriter(new OutputStreamWriter(RTSPsocket.getOutputStream()));
                    RTSPBufferedReader = new BufferedReader(new InputStreamReader(RTSPsocket.getInputStream()));
                    //%%%%%%%%%%%%%%%%%%%%%
                    //Start: Create Client RSAPublic Key
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(2048);
                    KeyPair kp = kpg.generateKeyPair();
                    KeyFactory fact = KeyFactory.getInstance("RSA");
                    RSAPublicKeySpec rsaPublicKeySpec = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
                    BigInteger n1  = rsaPublicKeySpec.getModulus();
                    BigInteger e  = rsaPublicKeySpec.getPublicExponent();
                    PublicKey Client_RSAPublicKey = generateRSAPublicKey(n1, e);
                    //End: Create Client RSAPublic Key
                    // Start: Send Client RSAPublic Key in string (S_Client_RSAPublicKey)
                    //byte[] publicKeyBytes =Client_RSAPublicKey.getEncoded();
                    //20181start
                    String S_Client_RSAPublicKey = null;
                    // S_Client_RSAPublicKey = Base64.encodeToString(Client_RSAPublicKey.getEncoded(), Base64.DEFAULT);
                    S_Client_RSAPublicKey = Base64.encodeToString(Client_RSAPublicKey.getEncoded(), Base64.NO_WRAP);
                    Log.d("VR", "S_Client_RSAPublicKey size  in string = " + S_Client_RSAPublicKey.length());
                    //String Modified_S = S_Client_RSAPublicKey.replaceAll(CRLF, " ");
                    String Modified_S1 =S_Client_RSAPublicKey.replaceAll("\n", "NNNNN");
                    String Modified_S3 = Modified_S1.replaceAll("\r", "RRRRR");
                    Log.d("VR", "Modified_S after  in string = " + Modified_S3);
                    Log.d("VR", "Modified_S3 length  in string = " + Modified_S3.length());
                    String lineSep = System.getProperty("line.separator");
                    //  RTSPBufferedWriterS.write(Modified_S3 + CRLF);
                    RTSPBufferedWriterS.write(S_Client_RSAPublicKey + CRLF);
                    RTSPBufferedWriterS.flush();
                    //Log.d("VR", "Packet Sent pub key length in string = " + new String(Modified_S3 +CRLF).length());
                    Log.d("VR", "Packet Sent pub key length in string = " + S_Client_RSAPublicKey);
                    //20181end
                    Log.d("VR", "before readline ");
                    final String NModifiedLine = RTSPBufferedReader.readLine();
                    Log.d("VR", " ModifiedLine from socket length in string " + NModifiedLine.length() );
                    //String RxLine2 =ModifiedLine.replaceAll("NNNNN", "\n");
                    // final String RxLine =RxLine2.replaceAll("RRRRR", "\r");
                    // Log.d("VR", " RxLine length in string " + RxLine.length() );
                    //  Log.d("VR", "Encrypted session key  in string  " + RxLine );
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            peerReply.setText("Peer Reply :  " + "received  key OK = " + NModifiedLine);
                        }
                    });
                    byte [] SessionBytes = Base64.decode(NModifiedLine, Base64.NO_WRAP);
                    //new end
                    //Start: Create Client RSAPrivate Key
                    RSAPrivateKeySpec rsaPrivateKeySpec = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
                    BigInteger n2  = rsaPrivateKeySpec.getModulus();
                    BigInteger d  = rsaPrivateKeySpec.getPrivateExponent();
                    PrivateKey Client_RSAPrivateKey = generateRSAPrivateKey(n2 , d);
                    //End: Create Client RSAPrivate Key
                    final byte[] DecryptedKey = decrypt(SessionBytes, Client_RSAPrivateKey);//3333
                    Log.d("VR", "3333");
                    // char[] rechars =  byte2CharArray(DecryptedKey);
                    // final String recovered_key = String.valueOf(rechars);
                    B_shared_key  = new String(DecryptedKey);//4444
                    Log.d("VR", "4444" + B_shared_key);
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            sharedkey.setText("Client Shared  Key =  " + B_shared_key);
                            Log.d("VR", "5555" + B_shared_key);
                        }
                    });
                } catch (SocketException e) {
                    Log.e("VR", "Sender SocketException");
                } catch (IOException e) {
// TODO Auto-generated catch block
                    e.printStackTrace();
                }
                catch (NoSuchAlgorithmException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                //catch (InvalidParameterSpecException e) {
                // TODO Auto-generated catch block
                // e.printStackTrace();
                //}
                // catch (InvalidAlgorithmParameterException e) {
                // TODO Auto-generated catch block
                //   e.printStackTrace();
                // }catch (InvalidKeyException e) {
                // TODO Auto-generated catch block
                //  e.printStackTrace();
                // }
                catch (InvalidKeySpecException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        });
        startClientThread.start();
    }
    public byte[] rc4_encrypt(byte[] clearText, String B_shared_key)throws  NoSuchAlgorithmException, InvalidKeyException, Throwable {
        byte[] clearText_;
        byte[] cipherText;
        byte[] returnText = new byte[clearText.length];
        int length=B_shared_key.length();
        if(length>16 && length!=16){
            B_shared_key=B_shared_key.substring(0, 15);
        }
        if(length<16 && length!=16){
            for(int i=0;i<16-length;i++){
                B_shared_key=B_shared_key+"0";
            }
        }
        try {
            Cipher rc4 = Cipher.getInstance("RC4");
            SecretKeySpec rc4Key = new SecretKeySpec(B_shared_key.getBytes(), "RC4");
            rc4.init(Cipher.ENCRYPT_MODE, rc4Key);
            cipherText = rc4.update(clearText);
            int counter = 0;
            while (counter < cipherText.length) {
                returnText[counter] = cipherText[counter];
                counter++;
            }
            return returnText;
        } catch (Exception e) { return null; }
    }
    public byte[] rc4_decrypt(byte[] ciphertext, String B_shared_key)throws  NoSuchAlgorithmException, InvalidKeyException, Throwable {
        byte[] clearText;
        byte[] cipherText = new byte[ciphertext.length];
        int length=B_shared_key.length();
        if(length>16 && length!=16){
            B_shared_key=B_shared_key.substring(0, 15);
        }
        if(length<16 && length!=16){
            for(int i=0;i<16-length;i++){
                B_shared_key=B_shared_key+"0";
            }
        }
        try {
            int counter = 0;
            while (counter < ciphertext.length) {
                cipherText[counter] = (byte)ciphertext[counter];
                counter++;
            }
            Cipher rc4 = Cipher.getInstance("RC4");
            SecretKeySpec rc4Key = new SecretKeySpec(B_shared_key.getBytes(), "RC4");
            rc4.init(Cipher.DECRYPT_MODE, rc4Key);
            clearText = rc4.update(cipherText);
            //System.out.println(new String(clearText, "ASCII"));
            return clearText;
        } catch (Exception e) { return null; }
    }
    private String getIpAddress() {
        String ip = "";
        try {
            Enumeration<NetworkInterface> enumNetworkInterfaces = NetworkInterface
                    .getNetworkInterfaces();
            while (enumNetworkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = enumNetworkInterfaces
                        .nextElement();
                Enumeration<InetAddress> enumInetAddress = networkInterface
                        .getInetAddresses();
                while (enumInetAddress.hasMoreElements()) {
                    InetAddress inetAddress = enumInetAddress.nextElement();
                    if (inetAddress.isSiteLocalAddress()) {
                        ip += inetAddress.getHostAddress() + "\n";
                    }
                }
            }
        } catch (SocketException e) {
// TODO Auto-generated catch block
            e.printStackTrace();
            ip += "Something Wrong! " + e.toString() + "\n";
        }
        return ip;
    }
    private static PublicKey generateRSAPublicKey(BigInteger n, BigInteger e) throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PublicKey RSAPublicKey  = fact.generatePublic(rsaPublicKeySpec);
        // TODO Auto-generated method stub
        return RSAPublicKey ;
    }
    private static PrivateKey generateRSAPrivateKey(BigInteger n, BigInteger d) throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(n, d);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey RSAPrivateKey = fact.generatePrivate(rsaPrivateKeySpec);
        // TODO Auto-generated method stub
        return RSAPrivateKey;
        // TODO Auto-generated method stub
    }
    public static byte[] decrypt(byte[] input, PrivateKey key) {
        byte[] decryptedKey = new byte[input.length];
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance("RSA");
            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedKey = cipher.doFinal(input);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return decryptedKey;
    }
    private static BigInteger getSharedKey(PublicKey pubKey,PrivateKey privKey)
            throws NoSuchAlgorithmException, InvalidKeyException  {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privKey);
        ka.doPhase(pubKey, true);
        byte[] b = ka.generateSecret();
        BigInteger secretKey  = new BigInteger(b);
        return secretKey ;
    }
    // public static byte[] encrypt(String text, PublicKey key) {
    public static byte[] encrypt(byte[] text, PublicKey key) {
        byte[] cipherText = new byte[text.length];
        Cipher cipher;
        try {
            // get an RSA cipher object and print the provider
            cipher = Cipher.getInstance("RSA");
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // cipherText = cipher.doFinal(text.getBytes());
            cipherText = cipher.doFinal(text);
            //string.getBytes(StandardCharsets.UTF_8)
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }
    public static byte[] charArray2ByteArray(char[] chars){
        int length = chars.length;
        byte[] result = new byte[length*2];
        int i = 0;
        for(int j = 0 ;j<chars.length;j++){
            result[i++] = (byte)( (chars[j] & 0xFF00) >> 8 );
            result[i++] = (byte)((chars[j] & 0x00FF)) ;
        }
        return result;
    }
    public static char[] byte2CharArray(byte[] data){
        char[] chars = new char[data.length/2];
        for(int i = 0 ;i<chars.length;i++){
            chars[i] = (char)( ((data[i*2] & 0xFF) << 8 ) + (data[i*2+1] & 0xFF)) ;
        }
        return chars;
    }
    /**
     * Converts a given datagram packet's contents to a String.
     */
    static String stringFromPacket(DatagramPacket packet) {
        return new String(packet.getData(), 0, packet.getLength());
    }
    /**
     * Converts a given String into a datagram packet.
     */
    static void stringToPacket(String s, DatagramPacket packet) {
        byte[] bytes = s.getBytes();
        System.arraycopy(bytes, 0, packet.getData(), 0, bytes.length);
        packet.setLength(bytes.length);
    }
    private class socketServerThread extends Thread {
        @SuppressLint("DefaultLocale")
        public void run(){
            try {
                //@SuppressWarnings("resource")
                serverSocket = new ServerSocket(RTSPPORT);
                DatagramSocket server_socket = new DatagramSocket(SERVER_PORT);
                RTSP_server_socket = serverSocket.accept();
                IPAddressClient = RTSP_server_socket.getInetAddress();
                RTSPBufferedReader = new BufferedReader(new InputStreamReader(RTSP_server_socket.getInputStream()));
                RTSPBufferedWriterS = new BufferedWriter(new OutputStreamWriter(RTSP_server_socket.getOutputStream()));
                //Start: Create Client RSAPublic Key
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                KeyFactory fact = KeyFactory.getInstance("RSA");
                RSAPublicKeySpec rsaPublicKeySpec = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
                BigInteger n1  = rsaPublicKeySpec.getModulus();
                BigInteger e  = rsaPublicKeySpec.getPublicExponent();
                PublicKey Client_RSAPublicKey = generateRSAPublicKey(n1, e);
                //End: Create Client RSAPublic Key
                Log.d("VR", "Sever Socket Created");
                //  byte[] receiveData = new byte[1024];
                //  DatagramPacket recv_packet = new DatagramPacket(receiveData, receiveData.length);
                while (true) {
                    Log.d("VR", "enter while ");
                    //Start: Receive Client RSAPublic Key in string
                    RequestLine = null;
                    Log.d("VR", "before readline ");
                    String ModifiedLine = RTSPBufferedReader.readLine();
                    Log.d("VR", " ModifiedLine from socket length in string " + ModifiedLine.length() );
                    //String RequestLine2 =ModifiedLine.replaceAll("NNNNN", "\n");
                    // RequestLine =RequestLine2.replaceAll("RRRRR", "\r");
                    Log.d("VR", " RequestLine length in string " + ModifiedLine.length() );
                    Log.d("VR", " public key  in string  " + ModifiedLine );
                    byte [] publicBytes = Base64.decode(ModifiedLine, Base64.NO_WRAP);
                    Log.d("VR", "publickey byte received length = " + publicBytes.length);
                    Log.d("VR", "publicBytes received length = " + publicBytes.length );
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    Log.d("VR", "keyFactory OK");
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
                    Log.d("VR", "keySpec OK");
                    // PublicKey Client_RSAPublicKey =  keyFactory.generatePublic(keySpec);
                    Client_RSAPublicKey =  keyFactory.generatePublic(keySpec);
                    Log.d("VR", "Client_RSAPublicKey OK");
                    //End: Convert Client RSAPublic Key in string to PublicKey
                    //Start: Generate random string
                    char[] chars = "123456789012345678901234".toCharArray();
                    StringBuilder sb = new StringBuilder();
                    Random random = new Random();
                    for (int i = 0; i < LEN_Key; i++) {
                        char c = chars[random.nextInt(chars.length)];
                        sb.append(c);
                    }
                    final String randomString = sb.toString();
                    B_shared_key2=randomString;
                    Log.d("VR", "B1" + randomString);
                    //End: Generate random string
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mConversationArrayAdapter.add("Server Shared key = "+randomString);
                        }
                    });
                    //new start
                    //First get the chars of the String,each char has two bytes(Java).
                    char[] random_chars;
                    random_chars = randomString.toCharArray();
                    Log.d("VR", "B2" + random_chars.toString());
//Get the bytes
                    byte[] random_bytes = charArray2ByteArray(random_chars);
                    // trans end
                    Log.d("VR", "B3" + random_bytes.toString());
                    byte[] EncryptedKeyB = encrypt(random_bytes, Client_RSAPublicKey);
                    // final  String S_EncryptedKey =  EncryptedKey.toString();
                    //final String Secure_sessionKey = Base64.encodeToString(EncryptedKeyB, Base64.DEFAULT);
                    final String Secure_sessionKey = Base64.encodeToString(EncryptedKeyB, Base64.NO_WRAP);
                    Log.d("VR", "Server Encrypted Shared key = " + Secure_sessionKey);
                    Log.d("VR", "Server Encrypted Shared key length = " + Secure_sessionKey.length());
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mConversationArrayAdapter.add("Server sent key = "+Secure_sessionKey);
                        }
                    });
                    // String Modified_S1 =Secure_sessionKey.replaceAll("\n", "NNNNN");
                    // String Modified_S3 = Modified_S1.replaceAll("\r", "RRRRR");
                    // Log.d("VR", "Modified_S after  in string = " + Modified_S3);
                    // Log.d("VR", "Modified_S3 length  in string = " + Modified_S3.length());
                    //String lineSep = System.getProperty("line.separator");
                    RTSPBufferedWriterS.write(Secure_sessionKey + CRLF);
                    RTSPBufferedWriterS.flush();
                    Log.d("VR", " Sent encrypted session key, length in string = " + Secure_sessionKey);
                }
            } //end of while
            catch (IOException e) {
// TODO Auto-generated catch block
                e.printStackTrace();
            }
            catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            //catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            // e.printStackTrace();
            // }
            catch (InvalidKeySpecException e) {
                // TODO Auto-generated catch block
                Log.d("VR", "Invalid key spec");
                e.printStackTrace();
            }
        }
    }
    /**
     * Converts a given datagram packet's contents to a String.
     */
    /**
     * Converts a given String into a datagram packet.
     */
    private static byte[] decodeBase64(byte[] encoded) throws IOException
    {
        try
        {
            return Base64.decode(encoded, Base64.DEFAULT);
        }
        catch (final IllegalArgumentException x)
        {
            throw new IOException("illegal base64 padding", x);
        }
    }
    public void startP2PSending() {
        Thread startP2PSendingThread = new Thread (new Runnable() {
            @Override
            public void run() {
                try {
                    MessageInput = inputMessage.getText().toString();
                    if(Callee == true){
                        PeerIP1 = PeerIP2;
                    }
                    else
                    {
                        PeerIP1 =  InetAddress.getByName(editPeerIP.getText().toString());
                        Log.d("VR",  "MessageInput" + MessageInput.getBytes());
                    }
                    final InetAddress peerIP = InetAddress.getByName(editPeerIP.getText().toString());
                    Log.d("VR",  "B_shared_key" + B_shared_key);
                    byte[] m1= new byte[1024];
                    try {
                        m1 = rc4_encrypt(MessageInput.getBytes(), B_shared_key);
                    } catch (Throwable throwable) {
                        throwable.printStackTrace();
                    }
                    DatagramPacket send_packet = new DatagramPacket(m1, MessageInput.length(),PeerIP1,RECV_PORT);
                    send_socket.send(send_packet);
                    Log.d("VR", "Encryt_Message" + m1);
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mConversationArrayAdapter.add("Sending from " + getIpAddress().trim() + " : " + inputMessage.getText().toString());
                        }
                    });
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            inputMessage.setText("");
                        }
                    });
                    //}
                } catch (SocketException e) {
                    Log.e("VR", "Sender SocketException");
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        });
        startP2PSendingThread.start();
    }
    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    private class StartReceiveThread extends Thread {
        DatagramSocket recv_socket;
        byte[] receiveData =new byte[1024];
        public void run() {
            try {
                recv_socket = new DatagramSocket(RECV_PORT);
                Log.d("VR", "Receiver Socket Created");
                while (true) {
                    DatagramPacket recv_packet = new DatagramPacket(receiveData, receiveData.length);
                    recv_socket.receive(recv_packet);
                    Log.d("VR", "Packet Received" + recv_packet.getData());
                    byte[] m2= new byte[1024];
                    try {
                        m2= rc4_decrypt(recv_packet.getData(), B_shared_key);
                    } catch (Throwable throwable) {
                        throwable.printStackTrace();
                    }
                    final String  receive_data = new String(m2, 0 , recv_packet.getLength());
                    Log.d("VR", "received data" + receive_data);
                    InetAddress sourceHost = recv_packet.getAddress() ;
                    PeerIP2 = sourceHost;
                    Callee = true;
                    final String sourceIP = sourceHost.getHostName();
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mConversationArrayAdapter.add("Message from " + sourceIP + " : " + receive_data);
                        }
                    });
                }
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }
}