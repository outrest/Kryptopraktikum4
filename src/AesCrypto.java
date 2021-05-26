
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class AesCrypto {

    private static String CIPHER_NAME = "AES/CBC/PKCS5PADDING";

    private static int CIPHER_KEY_LEN = 16; //128 bits

    /**
     * Encrypt data using AES Cipher (CBC) with 128 bit key
     *
     * @param key  - key to use should be 16 bytes long (128 bits)
     * @param iv   - initialization vector
     * @param data - data to encrypt
     * @return encryptedData data in base64 encoding with iv attached at end after a :
     */
    public static String encrypt(String key, String iv, String data) {

        try {
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec secretKey = new SecretKeySpec(fixKey(key).getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance(CIPHER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            byte[] encryptedData = cipher.doFinal((data.getBytes()));

            String encryptedDataInBase64 = Base64.getEncoder().encodeToString(encryptedData);
            String ivInBase64 = Base64.getEncoder().encodeToString(iv.getBytes(StandardCharsets.UTF_8));

            return encryptedDataInBase64 + ":" + ivInBase64;

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static String fixKey(String key) {

        if (key.length() < CIPHER_KEY_LEN) {
            int numPad = CIPHER_KEY_LEN - key.length();

            for (int i = 0; i < numPad; i++) {
                key += "0"; //0 pad to len 16 bytes
            }

            return key;

        }

        if (key.length() > CIPHER_KEY_LEN) {
            return key.substring(0, CIPHER_KEY_LEN); //truncate to 16 bytes
        }

        return key;
    }

    /**
     * Decrypt data using AES Cipher (CBC) with 128 bit key
     *
     * @param key  - key to use should be 16 bytes long (128 bits)
     * @param data - encrypted data with iv at the end separate by :
     * @return decrypted data string
     */

    public static String decrypt(String key, String data) {

        try {
            String[] parts = data.split(":");

            IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(parts[1]));
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance(CIPHER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            byte[] decodedEncryptedData = Base64.getDecoder().decode(parts[0]);

            byte[] original = cipher.doFinal(decodedEncryptedData);

            return new String(original);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static void main(String[] args) {

        String key = "0123456789abcdef"; // 128 bit key
        String initVector = "abcdef9876543210"; // 16 bytes IV, it is recommended to use a different random IV for every message!

        String plain_text = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34";
        String encrypted = encrypt(key, initVector, plain_text);
        System.out.println(Arrays.toString(encrypted.getBytes()));

        String decrypt = decrypt(key, encrypted);
        System.out.println(Arrays.toString(decrypt.getBytes()));
    }
}