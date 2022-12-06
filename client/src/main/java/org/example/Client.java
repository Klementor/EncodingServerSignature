package org.example;

import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class Client {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 3345);
             BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {
            System.out.println("Клиент подключен успешно.");
            System.out.println();
            while (!socket.isOutputShutdown()) {
                while (in.ready()) {
                    String wordsToHandle = in.readLine();
                    if (wordsToHandle.equalsIgnoreCase("SecretKey")) {
                        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                        Key key = (Key) ois.readObject();
                        Cipher encryptCipher = Cipher.getInstance("AES");
                        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
                        System.out.println("Введите свое сообщение");
                        String bytes = Base64.getEncoder()
                                .encodeToString(encryptCipher.doFinal(consoleReader.readLine().getBytes(StandardCharsets.UTF_8)));
                        out.write(bytes + "\n");
                        out.flush();
                    } else if (wordsToHandle.equalsIgnoreCase("KeyPair")) {
                        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                        Key key = (Key) ois.readObject();
                        System.out.println("Получение сообщения и подпись для проверки сервера...");
                        String serverCheck = (String) ois.readObject();
                        System.out.println("Полученное сообщение: \n - " + serverCheck);
                        System.out.println("Получение подписи...");
                        byte[] digitalSignature = (byte[]) ois.readObject();
                        Signature signature = Signature.getInstance("SHA1withRSA");
                        signature.initVerify((PublicKey) key);
                        signature.update(serverCheck.getBytes(StandardCharsets.UTF_8));
                        boolean verified = signature.verify(digitalSignature);
                        System.out.println("Подпись: " + verified);
                        System.out.println("Запишите сообщение для шифрования ");
                        String textToEncrypt = consoleReader.readLine();
                        Cipher encryptCipher = Cipher.getInstance("RSA");
                        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
                        String bytes = Base64
                                .getEncoder().encodeToString(encryptCipher.doFinal(textToEncrypt.getBytes(StandardCharsets.UTF_8)));
                        out.write(bytes + "\n");
                        out.flush();
                        Thread.sleep(100);
                    } else if (wordsToHandle.equalsIgnoreCase("disconnect")) {
                        return;
                    } else System.out.println(wordsToHandle);
                }
                if (consoleReader.ready()) {
                    String word = consoleReader.readLine();
                    out.write(word + "\n");
                    out.flush();
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}