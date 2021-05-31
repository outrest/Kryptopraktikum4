
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Aufgabe1 {


    public static void main(String[] args) {

        byte[] blarkInput = {0x32, 0x43, (byte) 0xf6, (byte) 0xa8, (byte) 0x88, 0x5a, 0x30, (byte) 0x8d, 0x31, 0x31, (byte) 0x98, (byte) 0xa2, (byte) 0xe0, 0x37, 0x07, 0x34};

        byte[] key_byte = {0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c};

        byte[] se_real_fips197 = {0x39, 0x25, (byte) 0x84, 0x1d, 0x02, (byte) 0xdc, 0x09, (byte) 0xfb, (byte) 0xdc, 0x11,(byte) 0x85, (byte) 0x97, 0x19, 0x6a, 0x0b, 0x32};

        for (byte etwas : se_real_fips197){
            System.out.print(String.format("%x",Byte.toUnsignedInt(etwas))+ " ");
        }
        System.out.println("\n----------------------------------");

        SecretKeySpec key = new SecretKeySpec(key_byte, "AES");
        try {
            Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, key);
            byte[] AES_byte = aes.doFinal(blarkInput);
            for (byte etwas:AES_byte){
                System.out.print(String.format("%x",Byte.toUnsignedInt(etwas))+ " ");
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
} // (String.format("%x", blark)
