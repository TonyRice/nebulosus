package io.nebulosus.util;

import io.jsync.Handler;
import io.jsync.buffer.Buffer;
import io.jsync.json.impl.Base64;
import io.jsync.utils.CryptoUtils;
import io.jsync.utils.Token;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

/**
 * This is just a simple utility class providing some crypto features used throughout Nebulosus and the Evaporation
 * Protocol.
 */
public class CryptoUtil {

    final public static int DEFAULT_KEYPAIR_SIZE = 8192;
    final public static String DEFAULT_SECRET_KEY_SPEC = "AES";
    final public static String DEFAULT_KEY_FACTORY = "PBKDF2WithHmacSHA512";
    final public static String DEFAULT_CIPHER = "AES/CBC/PKCS5Padding";

    final public static int DEFAULT_CIPHER_KEY_SIZE = 128;

    public static Random getSecureRandom(){
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This will generate a very strong and secure password. This really isn't all that secure..
     *
     * @return returns a randomly generated SHA512 string
     */
    public static String generateRandomPassword(){
        try {
            SecureRandom sr = SecureRandom.getInstanceStrong();
            byte[] salt = new byte[512];
            sr.nextBytes(salt);
            String password = Token.generateToken().toHex() + Token.generateToken().toHex();
            return CryptoUtils.calculateHmacSHA512(password + password, CryptoUtils.calculateSHA512(salt));
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    /**
     * This will generate a SecretKey based on a password and a salt.
     *
     * @param password the password
     * @param salt the salt
     * @return returns a SecretKey
     */
    public static SecretKey generateSecretKey(String password, byte[] salt){
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(DEFAULT_KEY_FACTORY);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, DEFAULT_CIPHER_KEY_SIZE);
            SecretKey tmp = factory.generateSecret(spec);
            return new  SecretKeySpec(tmp.getEncoded(), DEFAULT_SECRET_KEY_SPEC);
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    /**
     * This will generate a secret key with a given password and a new random salt.
     *
     * @param password the password you wish to generate the SecretKeyWith
     * @param saltHandler this will be triggered when the new salt is generated
     * @return returns a newly generated SecretKey
     */
    public static SecretKey generateSecretKey(String password, Handler<byte[]> saltHandler){
        try {
            byte[] salt = generateSalt();
            if(saltHandler != null){
                saltHandler.handle(salt);
            }
            return generateSecretKey(password, salt);
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    /**
     * This will generate a random salt.
     *
     * @return the salt!
     */
    public static byte[] generateSalt(){
        try {
            SecureRandom sr = SecureRandom.getInstanceStrong();
            byte[] salt = new byte[64];
            sr.nextBytes(salt);
            return salt;
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    /**
     * This will go ahead and decrypt a buffer previously encrypted along
     * with the IV stored.
     *
     * @param key the SecretKey you wish to use
     * @param data the data you wish to decrypt
     * @return returns a decrypted Buffer
     */
    public static Buffer decrypt(SecretKey key, Buffer data) {
        try {
            int pos;
            int dataLen = data.getInt(pos = 0);
            pos += 4;
            byte[] encrypted = data.getBytes(pos, dataLen + pos);
            pos += dataLen;
            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER);
            int ivLen = data.getInt(pos);
            pos += 4;
            byte[] ivData = data.getBytes(pos, pos + ivLen);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivData);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return new Buffer(cipher.doFinal(encrypted));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This will go ahead and encrypt a Buffer with the given
     * SecretKey. The buffer returned has the IV and the encrypted
     * data stored along with it.
     *
     * @param key the SecretKey you wish to use
     * @param data the data you wish to encrypt
     *
     * @return returns a new Buffer with the encrypted data
     */
    public static Buffer encrypt(SecretKey key, Buffer data) {
        try {
            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER);
            byte[] ivData = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivData);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            Buffer newData = new Buffer();
            newData.appendInt(encrypted.length);
            newData.appendBytes(encrypted);
            newData.appendInt(ivData.length);
            newData.appendBytes(ivData);
            return newData;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This will decrypt a Buffer using a specified RSA PrivateKey.
     *
     * @param privateKey the private key you wish to use
     * @param data the data you wish to decrypt
     * @return the decrypted data
     */
    public static Buffer decryptRSA(PrivateKey privateKey, Buffer data) {
        try {
            final Cipher cipher = Cipher.getInstance("RSA");

            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            Buffer curBuffer = new Buffer();
            curBuffer.appendBuffer(data);
            int bytesRead = 0;
            do {
                int len = (curBuffer.length() > 1024 ? bytesRead + 1024 : curBuffer.length());
                cipher.update(curBuffer.getBytes(bytesRead, len));
                bytesRead += len;
            } while (bytesRead < curBuffer.length());

            return new Buffer(cipher.doFinal());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This will encrypt a Buffer using a specified RSA PublicKey.
     *
     * @param publicKey the public key you wish to use
     * @param data the data you wish to encrypt
     * @return the encrypted data
     */
    public static Buffer encryptRSA(PublicKey publicKey, Buffer data) {
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            Buffer curBuffer = new Buffer();
            curBuffer.appendBuffer(data);
            int bytesRead = 0;
            do {
                int len = (curBuffer.length() > 1024 ? bytesRead + 1024 : curBuffer.length());
                cipher.update(curBuffer.getBytes(bytesRead, len));
                bytesRead += len;
            } while (bytesRead < curBuffer.length());

            byte[] encrypted = cipher.doFinal();
            return new Buffer(encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey generateRSAPublicKey(byte[] data) {
        try {
            X509EncodedKeySpec spec =
                    new X509EncodedKeySpec(data);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Buffer signRSA(Buffer data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA512withRSA");
            signature.initSign(privateKey);
            Buffer curBuffer = new Buffer();
            curBuffer.appendBuffer(data);
            int bytesRead = 0;
            do {
                int len = (curBuffer.length() > 1024 ? bytesRead + 1024 : curBuffer.length());
                signature.update(curBuffer.getBytes(bytesRead, len));
                bytesRead += len;
            } while (bytesRead < curBuffer.length());
            byte[] signatureData = signature.sign();
            return new Buffer(signatureData);
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    public static boolean verifyRSA(Buffer signatureData, Buffer data, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA512withRSA");
            signature.initVerify(publicKey);
            Buffer curBuffer = new Buffer();
            curBuffer.appendBuffer(data);
            int bytesRead = 0;
            do {
                int len = (curBuffer.length() > 1024 ? bytesRead + 1024 : curBuffer.length());
                signature.update(curBuffer.getBytes(bytesRead, len));
                bytesRead += len;
            } while (bytesRead < curBuffer.length());
            return signature.verify(signatureData.getBytes());
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }
}
