package org.example;

import javax.crypto.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class Server {
    private final static int KEYBITESIZE = 256;

    private static Socket clientSocket;
    //private static ServerSocket server;
    private static BufferedReader in;
    private static BufferedWriter out;

    public static void main(String[] args) {
        try (ServerSocket server = new ServerSocket(3345)) {
            clientSocket = server.accept();
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
            while (clientSocket.isConnected()) {
                out.write("Выберите желаемое действие: \n");
                out.write("1 - Асимметричное шифрование RSA \n");
                out.write("2 - Симметричное шифрование AES \n");
                out.write("3 - Выход из программы \n");
                out.flush();
                int caseN = -1;
                try {
                    caseN = Integer.parseInt(in.readLine());
                } catch (Exception e) {
                    out.write("Вы ввели неподходящее число:(\n\n");
                    out.flush();
                }
                switch (caseN) {
                    case 1 -> asymEncryption();
                    case 2 -> symEcryption();
                    case 3 -> {
                        out.write("Вы будете отключены...");
                        out.flush();
                    }
                    default -> {
                    }
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void asymEncryption() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InterruptedException, SignatureException {
        out.write("---------------------------------\n");
        out.write("Вы выбрали асимметричное шифрование!\n");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2056);
        KeyPair keyPair = kpg.generateKeyPair();
        out.write("У вас есть публичный ключ для зашифровки сообщения\n");
        out.write("KeyPair\n");
        out.flush();
        Thread.sleep(300);
        ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
        oos.writeObject(keyPair.getPublic());
        out.flush();

        Thread.sleep(100);
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(keyPair.getPrivate(), new SecureRandom());
        String signatureCheck = "Проверка подписи для клиента";
        oos.writeObject(signatureCheck);
        oos.flush();

        Thread.sleep(100);
        byte[] data = signatureCheck.getBytes("UTF-8");
        signature.update(data);
        byte[] digitalSignature = signature.sign();
        oos.writeObject(digitalSignature);
        oos.flush();

        String entry = in.readLine();
        out.write("Сервер получил зашифрованное сообщение: " + entry);
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] bytes = encryptCipher.doFinal(Base64.getDecoder().decode(entry));
        out.write("\nРасшифровка...");
        out.flush();
        Thread.sleep(1000);
        out.write("\nПолучилось!\nСообщение: \"" + new String(bytes, StandardCharsets.UTF_8) + "\"\n\n\n");
        out.flush();
        Thread.sleep(1500);
    }

    private static void symEcryption() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InterruptedException {
        out.write("---------------------------------\n");
        out.write("Вы выбрали симметричное шифрование!\n");
        out.write("У вас есть ключ для шифрования сообщения!\n");
        out.flush();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEYBITESIZE, new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        out.write("SecretKey\n");
        out.flush();
        Thread.sleep(500);
        ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
        oos.writeObject(secretKey);
        out.flush();
        //Получаю зашифрованное сообщение
        String entry = in.readLine();
        out.write("Сервер получил зашифрованное сообщение: " + entry);
        out.write("\nРасшифровка...\n");
        out.flush();
        Thread.sleep(1000);
        Cipher decryptCipher = Cipher.getInstance("AES");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] bytes = decryptCipher.doFinal(Base64.getDecoder().decode(entry));
        out.write("Получилось!\nСообщение: " + new String(bytes, StandardCharsets.UTF_8));
        out.write("\n\n\n");
        out.flush();
        Thread.sleep(2000);
    }
}
