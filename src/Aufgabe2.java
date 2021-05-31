import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.Buffer;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.stream.Stream;

public class Aufgabe2 {
    public static void main(String[] args) throws IOException, InvalidKeyException {

        byte[] key_byte = {0x00, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
        byte[] iv = {(byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b, (byte) 0x8c, (byte) 0x8d, (byte) 0x8f};


        ByteArrayInputStream br = new ByteArrayInputStream(new FileInputStream("src\\chiffrat_AES.bin").readAllBytes());
        BufferedInputStream bsr = new BufferedInputStream(br);


        try {
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key;
            byte[] AES_byte;

            for (int i = 0; i < 256; i++) {
                for (int j = 0; j < 256; j++) {
                    key_byte[0] = (byte) i;
                    key_byte[1] = (byte) j;
                    key = new SecretKeySpec(key_byte, "AES");
                    aes.init(Cipher.DECRYPT_MODE, key);
                    AES_byte = aes.doFinal(bsr.readAllBytes());
                    if (checkMyBeginning(AES_byte)) {
                        System.out.println("Key: ");
                        for (byte etwas : AES_byte) {
                            System.out.print(String.format("%x", Byte.toUnsignedInt(etwas)) + " ");
                        }

                        break;
                    }
                }
            }

        } catch (Exception e) {
            System.out.println(e);
        }

    }

    //%pdf
    private static boolean checkMyBeginning(byte[] lol) {
        return ((lol[0] == 37) && (lol[1] == 112) && (lol[2] == 100) && (lol[3] == 102));
    }
}