
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

public class Aufgabe1 {

    public static void main(String[] args) {
        String input = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34";
        byte[] input_byte = input.getBytes(StandardCharsets.UTF_8);

        String key_string = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
        byte[] key_byte = key_string.getBytes(StandardCharsets.UTF_8);

        SecretKeySpec key = new SecretKeySpec(key_byte, "AES");
/*
        try {
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aes.init(Cipher.ENCRYPT_MODE, key);


        } catch (Exception E) {
            System.out.println("Et Cipher hat Mist jebaut!");
        }*/

        String encryptedString = AES.encrypt(input, key_string);
        String decryptedString = AES.decrypt(encryptedString, key_string);

        System.out.println(input);
        System.out.println(Arrays.toString(encryptedString.getBytes()));
        System.out.println(Arrays.toString(decryptedString.getBytes()));
    }

}
