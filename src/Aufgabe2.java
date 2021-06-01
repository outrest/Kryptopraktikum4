import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.Buffer;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.stream.Stream;

public class Aufgabe2 {
    public static void main(String[] args) throws IOException, InvalidKeyException {
// 52, 9a
        byte[] key_byte = {0x00, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
        key_byte = new byte[]{82, -102, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85};
        byte[] iv = {(byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b, (byte) 0x8c, (byte) 0x8d, (byte) 0x8e, (byte) 0x8f};


        ByteArrayInputStream br = new ByteArrayInputStream(new FileInputStream("src\\chiffrat_AES.bin").readAllBytes());
        BufferedInputStream bsr = new BufferedInputStream(br);
        byte[] chiffrat = bsr.readAllBytes();
        bsr.close();

        try {
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key;
            byte[] AES_byte;
            IvParameterSpec invec = new IvParameterSpec(iv);
            /*
            for (int i = 0; i < 256; i++) {
                key_byte[0] = (byte) i;
                for (int j = 0; j < 256; j++) {
                    key_byte[1] = (byte) j;*/
            key = new SecretKeySpec(key_byte, "AES");
            aes.init(Cipher.DECRYPT_MODE, key, invec);
            try {
                AES_byte = aes.doFinal(chiffrat);
                if (checkMyBeginning(AES_byte)) {
                    System.out.println("Key: " + Arrays.toString(key_byte));
                    for (byte etwas : key_byte) {
                        System.out.print(String.format("%x", Byte.toUnsignedInt(etwas)) + " ");
                    }
                    writeText(Arrays.toString(AES_byte),"crackedPDF");
                    // break;
                }
            } catch (BadPaddingException e) {
                aes = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            }
            //}
            //  }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    //  Key: [82, -102, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85]
    //%PDF => 25 50 44 46  <- Dat is Hex, ne?
    private static boolean checkMyBeginning(byte[] lol) {
        if (lol == null || lol.length == 0)
            return false;
        return lol[lol.length - 1] == 0x0A;
        //((lol[0] == 0x25) && (lol[1] == 0x50) && (lol[2] == 0x44) && (lol[3] == 0x46));
    }

    public static void writeText(String text, String filename){
        try{
            File ausgabeDatei = new File("src\\" + filename + ".pdf");
            if(!ausgabeDatei.isFile()){
                ausgabeDatei.createNewFile();
            }
            FileWriter ausgabeDateiSchreiben = new FileWriter("src\\" + filename + ".pdf");
            ausgabeDateiSchreiben.write(text);
            ausgabeDateiSchreiben.close();
            System.out.println("Erfolgreich geschrieben: " + ausgabeDatei.getName());

        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
