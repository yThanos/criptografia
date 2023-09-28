package br.ufsm.csi.assinatura;

import javax.crypto.*;
import javax.swing.*;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Alice {

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

        //par de chaves RSA alice
        KeyPairGenerator kpg =KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair rSAKeys = kpg.generateKeyPair();

        //escolhe arquivo para enviar
        JFileChooser fc = new JFileChooser("");
        if (fc.showDialog(new JFrame(), "OK") == JFileChooser.APPROVE_OPTION) {
            File f = fc.getSelectedFile();
            FileInputStream fin = new FileInputStream(f);

            //byte array do arquivo
            byte[] bArray = new byte[(int) fin.getChannel().size()];
            fin.read(bArray);
            fin.close();

            //abre socket para fazer a conexão com bob
            Socket s = new Socket("localhost", 5555);

            //recebe chave publica de bob
            ObjectInputStream oin = new ObjectInputStream(s.getInputStream());
            PublicKey publicKey = (PublicKey) oin.readObject();

            //gera chave de sessão AES
            KeyGenerator keyGeneratorAES = KeyGenerator.getInstance("AES");
            keyGeneratorAES.init(256);
            SecretKey chaveAES = keyGeneratorAES.generateKey();


            Cipher cipherRSA = Cipher.getInstance("RSA");
            Cipher cipherAES = Cipher.getInstance("AES");

            //cifra o arquivo com a chave de sessão
            cipherAES.init(Cipher.ENCRYPT_MODE, chaveAES);
            byte[] textoCifrado = cipherAES.doFinal(bArray);

            //cifra a chave de sessao com a chave do bob
            cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] chaveCifrada = cipherRSA.doFinal(chaveAES.getEncoded());

            //objeto a ser enviado para bob
            ObjetoTroca objetoTroca = new ObjetoTroca();
            objetoTroca.setArquivoCriptografado(textoCifrado);
            objetoTroca.setNomeArquivo(f.getName());
            objetoTroca.setChaveSessao(chaveCifrada);
            objetoTroca.setKey(rSAKeys.getPublic());

            //byte array do objeto
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(objetoTroca);
            oos.close();
            baos.close();
            byte[] objetoSerializado = baos.toByteArray();

            //hash do byte array do objeto
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(objetoSerializado);

            //assinatura do hash com chave privada da alice
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, rSAKeys.getPrivate());
            byte[] assinatura = cipher.doFinal(hash);
            objetoTroca.setAssinatura(assinatura);

            //envia para bob
            ObjectOutputStream oout = new ObjectOutputStream(s.getOutputStream());
            oout.writeObject(objetoTroca);
            s.close();

        }
    }

}
