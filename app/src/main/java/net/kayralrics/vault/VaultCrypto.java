package net.kayralrics.vault;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Byte-for-byte compatible with Fedora vault format v1. No network or OS keystore dependency. */
public final class VaultCrypto {
    private static final byte[] INDEX_MAGIC = "KVI1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] BLOB_MAGIC = "KVB1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] INDEX_AAD = "kayralrics-vault:index:v1".getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RNG = new SecureRandom();
    private static final int CHUNK = 65536;

    private VaultCrypto() { }

    public static byte[] random(int bytes) {
        byte[] data = new byte[bytes];
        RNG.nextBytes(data);
        return data;
    }

    public static byte[] derive(char[] password, byte[] salt, int n) {
        if (salt.length != 16 || n < 16384 || n > 262144 || (n & (n - 1)) != 0) {
            throw new IllegalArgumentException("Unsupported KDF settings");
        }
        byte[] input = new String(password).getBytes(StandardCharsets.UTF_8);
        try {
            return SCrypt.generate(input, salt, n, 8, 1, 32);
        } finally {
            Arrays.fill(input, (byte) 0);
        }
    }

    public static byte[] encryptIndex(byte[] key, byte[] plain) throws GeneralSecurityException, IOException {
        byte[] nonce = random(12);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        aes.updateAAD(INDEX_AAD);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(INDEX_MAGIC);
        result.write(nonce);
        result.write(aes.doFinal(plain));
        return result.toByteArray();
    }

    public static byte[] decryptIndex(byte[] key, byte[] encrypted) throws GeneralSecurityException, IOException {
        if (encrypted.length < 32 || !startsWith(encrypted, INDEX_MAGIC)) {
            throw new IOException("Invalid encrypted index header");
        }
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(encrypted, 4, 16)));
        aes.updateAAD(INDEX_AAD);
        return aes.doFinal(encrypted, 16, encrypted.length - 16);
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        for (int i = 0; i < prefix.length; i++) if (data[i] != prefix[i]) return false;
        return true;
    }

    private static GCMBlockCipher cipher(boolean encrypt, byte[] key, byte[] nonce, String id) {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        byte[] aad = ("kayralrics-vault:blob:v1:" + id).getBytes(StandardCharsets.US_ASCII);
        gcm.init(encrypt, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
        return gcm;
    }

    /** Encrypt a streaming source into an independent app-private file. Returns plaintext byte size. */
    public static long encryptBlob(byte[] key, String id, InputStream input, File destination) throws Exception {
        byte[] nonce = random(12);
        GCMBlockCipher enc = cipher(true, key, nonce, id);
        long size = 0;
        try (FileOutputStream out = new FileOutputStream(destination)) {
            out.write(BLOB_MAGIC);
            out.write(nonce);
            byte[] inputBuf = new byte[CHUNK];
            byte[] outputBuf = new byte[CHUNK + 32];
            int bytes;
            while ((bytes = input.read(inputBuf)) != -1) {
                if (bytes == 0) continue;
                size += bytes;
                int n = enc.processBytes(inputBuf, 0, bytes, outputBuf, 0);
                if (n > 0) out.write(outputBuf, 0, n);
            }
            try {
                int n = enc.doFinal(outputBuf, 0);
                if (n > 0) out.write(outputBuf, 0, n);
            } catch (InvalidCipherTextException ex) {
                throw new IOException("Encryption failed", ex);
            }
            out.getFD().sync();
        }
        return size;
    }

    /**
     * Decrypt in constant memory. Call verifyBlob BEFORE writing to a public destination,
     * so unauthenticated plaintext never reaches a public file.
     */
    public static long decryptBlob(byte[] key, String id, File source, OutputStream output) throws Exception {
        if (source.length() < 32) throw new IOException("Truncated encrypted file");
        try (InputStream in = new FileInputStream(source)) {
            byte[] header = new byte[16];
            readFully(in, header);
            if (!startsWith(header, BLOB_MAGIC)) throw new IOException("Invalid encrypted file header");
            GCMBlockCipher dec = cipher(false, key, Arrays.copyOfRange(header, 4, 16), id);
            byte[] buf = new byte[CHUNK];
            byte[] outBuf = new byte[CHUNK + 32];
            int bytes;
            long total = 0;
            while ((bytes = in.read(buf)) != -1) {
                if (bytes == 0) continue;
                try {
                    int n = dec.processBytes(buf, 0, bytes, outBuf, 0);
                    if (n > 0) { output.write(outBuf, 0, n); total += n; }
                } catch (RuntimeException ex) {
                    throw new IOException("Encrypted file processing failed", ex);
                }
            }
            try {
                int n = dec.doFinal(outBuf, 0);
                if (n > 0) { output.write(outBuf, 0, n); total += n; }
            } catch (InvalidCipherTextException ex) {
                throw new AEADBadTagException("Encrypted file failed authentication");
            }
            return total;
        }
    }

    public static long verifyBlob(byte[] key, String id, File source) throws Exception {
        return decryptBlob(key, id, source, new OutputStream() {
            @Override public void write(int b) { }
            @Override public void write(byte[] b, int off, int len) { }
        });
    }

    public static byte[] previewBlob(byte[] key, String id, File source, long limit) throws Exception {
        if (source.length() - 32 > limit) throw new IOException("Image is too large to preview");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        decryptBlob(key, id, source, out);
        return out.toByteArray();
    }

    public static void readFully(InputStream in, byte[] target) throws IOException {
        int pos = 0;
        while (pos < target.length) {
            int n = in.read(target, pos, target.length - pos);
            if (n < 0) throw new IOException("Unexpected end of data");
            pos += n;
        }
    }
}
