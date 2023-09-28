package br.ufsm.csi.assinatura;

import java.io.Serializable;
import java.security.PublicKey;

public class ObjetoTroca implements Serializable {

    private String nomeArquivo;
    private byte[] arquivoCriptografado;
    private byte[] chaveSessao;
    private byte[] assinatura;
    private PublicKey key;

    public PublicKey getKey() {
        return key;
    }

    public void setKey(PublicKey key) {
        this.key = key;
    }

    public String getNomeArquivo() {
        return nomeArquivo;
    }

    public void setNomeArquivo(String nomeArquivo) {
        this.nomeArquivo = nomeArquivo;
    }

    public byte[] getArquivoCriptografado() {
        return arquivoCriptografado;
    }

    public void setArquivoCriptografado(byte[] arquivoCriptografado) {
        this.arquivoCriptografado = arquivoCriptografado;
    }

    public byte[] getChaveSessao() {
        return chaveSessao;
    }

    public void setChaveSessao(byte[] chaveSessao) {
        this.chaveSessao = chaveSessao;
    }

    public byte[] getAssinatura() {
        return assinatura;
    }

    public void setAssinatura(byte[] assinatura) {
        this.assinatura = assinatura;
    }
}
