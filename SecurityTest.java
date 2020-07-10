import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class SecurityTest {

    public static void main(String[] a) 
    {
        SecurityTest test = new SecurityTest();
        String requestData = "{\"entityId\": “9328431416”}";
        try 
        {
            test.encodeRequest(requestData, "1234123412341278", "OXYGEN");
            Map<String, String> responseMap = new HashMap<>();
        } catch (Exception e) 
        {
            e.printStackTrace();
        }
    }

    public String encodeRequest(String requestData, String messageRefNo, String entity) throws Exception 
    {
        byte[] sessionKeyByte = this.generateToken();
        String data = " token:" + this.generateDigitalSignedToken(requestData) + ", body: "
                + this.encryptData(requestData, sessionKeyByte, messageRefNo) + ", entity:"
                + this.encryptKey(entity.getBytes()) + ",key: " + this.encryptKey(sessionKeyByte) + ", refNo:"
            + messageRefNo;
        System.out.println(data);
        return data;
    }

    public String encryptData(String requestData, byte[] sessionKey, String messageRefNo) throws Exception 
    {
        SecretKey secKey = new SecretKeySpec(sessionKey, "AES");
        Cipher cipher = Cipher.getInstance(symmetricKeyAlgorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(messageRefNo.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secKey, ivSpec);
        byte[] newData = cipher.doFinal(requestData.getBytes());
        return Base64.getEncoder().encodeToString(newData);
    }

    public String encryptKey(byte[] sessionKey) throws Exception 
    {
        PublicKey pubKey = readPublicKeyFromFile(m2pPublicFile);
        Cipher cipher = Cipher.getInstance(asymmetricKeyAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherData = cipher.doFinal(sessionKey);
        return Base64.getEncoder().encodeToString(cipherData);
    }

    public byte[] generateToken() throws Exception 
    {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        SecretKey key = generator.generateKey();
        String testkey = "1234123412341278";
        byte[] symmetricKey = testkey.getBytes();
        return symmetricKey;

    }

    public String generateDigitalSignedToken(String requestData) throws Exception 
    {
        Signature signature = Signature.getInstance(digitalSignatureAlgorithm);
        PrivateKey privateKey = this.readPrivateKeyFromFile(busPrivateFile);
        signature.initSign(privateKey, new SecureRandom());
        byte[] message = requestData.getBytes();
        signature.update(message);
        byte[] sigBytes = signature.sign();
        return Base64.getEncoder().encodeToString(sigBytes);
    }

    private PrivateKey readPrivateKeyFromFile(String keyFileName) throws Exception 
    {
        File filePrivateKey = new File(keyFileName);
        FileInputStream fis = new FileInputStream(filePrivateKey);
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }

    private PublicKey readPublicKeyFromFile(String keyFileName) throws Exception 
    {
        File filePublicKey = new File(keyFileName);
        FileInputStream fis = new FileInputStream(filePublicKey);
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }

    public String decodeResponse(Map responseMap) throws Exception 
    {
        String messageRefNo = responseMap.get("refNo").toString();
        String sessionKey = responseMap.get("key").toString();
        String token = responseMap.get("hash").toString();
        String body = responseMap.get("body").toString();
        return this.decryptMessage(body,sessionKey, token, messageRefNo);
    }

    public String decryptMessage(String xmlResponse, String encSessionKey, String token, String messageRefNo) throws Exception 
    {
        byte[] sessionKey = this.decryptSessionKey(encSessionKey);
        String data = decryptWithAESKey(xmlResponse, sessionKey, messageRefNo.getBytes());
        return data;
    }

    private String decryptWithAESKey(String inputData, byte[] key, byte[] iv)
            throws Exception 
    {
        Cipher cipher = Cipher.getInstance(symmetricKeyAlgorithm);
        SecretKeySpec secKey = new SecretKeySpec(key, symmetricKeyAlgorithm);
        IvParameterSpec spec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secKey, spec);
        byte[] newData = cipher.doFinal(Base64.getDecoder().decode(inputData));
        return new String(newData);
    }

    private byte[] decryptSessionKey(String sessionKey) throws Exception 
    {
        PrivateKey privateKey = readPrivateKeyFromFile(busPrivateFile);
        Cipher cipher = Cipher.getInstance(asymmetricKeyAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipher.update(Base64.getDecoder().decode(sessionKey));
        byte[] sessionKeyBytes = cipher.doFinal();
        return sessionKeyBytes;
    }

    private String m2pPublicFile = "E:/TECH/YAP Security Latest/yap_pub/m2psolutions_pub.der";
    private String busPrivateFile = "E:/TECH/FPLABS/prepaid.FPLABS.com" + ".pkcs8";
    private String symmetricKeyAlgorithm = "AES/CBC/PKCS5Padding";
    private String asymmetricKeyAlgorithm = "RSA/ECB/PKCS1Padding";
    private String digitalSignatureAlgorithm = "SHA1withRSA";
    private String pkiProvider = "BC";
}