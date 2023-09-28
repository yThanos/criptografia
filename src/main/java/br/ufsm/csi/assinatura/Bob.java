package br.ufsm.csi.assinatura;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Bob {

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        
        //gera o par de chaves do bob
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        //aguarda conexão da alice para enviar a chave publica
        ServerSocket ss = new ServerSocket(5555);
        Socket s = ss.accept();

        //evia a chave publica para alice
        ObjectOutputStream oout = new ObjectOutputStream(s.getOutputStream());
        oout.writeObject(keyPair.getPublic());

        //recebe o objeto de troca
        ObjectInputStream oin = new ObjectInputStream(s.getInputStream());
        ObjetoTroca objetoTroca = (ObjetoTroca) oin.readObject();

        //pega a assinatura e descriptografa com a chave q veio no objeto
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, objetoTroca.getKey());
        byte[] assinatura = cipher.doFinal(objetoTroca.getAssinatura());

        //remove a assinatura do objeto
        objetoTroca.setAssinatura(null);

        //gera o hash do objeto sem assinatura
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(objetoTroca);
        oos.close();
        baos.close();
        byte[] objetoSerializado = baos.toByteArray();
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(objetoSerializado);

        //compara o hash gerado com a assinatura
        if(hash != assinatura){

            //descriptografa a chave de sessão com a chave privada do bob
            Cipher cipherRSA = Cipher.getInstance("RSA");
            cipherRSA.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] chaveSessao = cipherRSA.doFinal(objetoTroca.getChaveSessao());
            SecretKey keyAES = new SecretKeySpec(chaveSessao, "AES");

            //descriptografa o arquivo com a chave de sessão
            Cipher cipherAES = Cipher.getInstance("AES");
            cipherAES.init(Cipher.DECRYPT_MODE, keyAES);
            byte[] textoPlano = cipherAES.doFinal(objetoTroca.getArquivoCriptografado());

            //salva o arquivo
            FileOutputStream fout = new FileOutputStream(objetoTroca.getNomeArquivo());
            fout.write(textoPlano);
            fout.close();
        }
        s.close();
        ss.close();
    }


}
