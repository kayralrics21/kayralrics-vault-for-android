package net.kayralrics.vault;

import org.junit.Test;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import static org.junit.Assert.*;

public class CryptoCompatibilityTest {
    private static byte[] hex(String s) {
        byte[] out = new byte[s.length()/2];
        for (int i = 0; i < out.length; i++) out[i] = (byte)Integer.parseInt(s.substring(i*2,i*2+2), 16);
        return out;
    }

    private final byte[] salt = hex("000102030405060708090a0b0c0d0e0f");
    private final byte[] expectedKey = hex("7a8e34241db898d59175c696538c417467a975ffe569068425f16188d3159c58");
    private final String id = "0123456789abcdef0123456789abcdef";

    @Test public void fedoraScryptAndIndexInterop() throws Exception {
        byte[] key = VaultCrypto.derive("correct horse battery staple".toCharArray(), salt, 32768);
        assertArrayEquals(expectedKey, key);
        byte[] index = hex("4b564931000102030405060708090a0bb42c8195008f0db3e6c229100159a9ff48afdbf61aa9c0bcfc03d06acfc0878f9465d307a9548947e0a623d3f1d72e605213b2ffaa8f0e395726ca7b");
        assertEquals("{\"schema\":1,\"notes\":{},\"files\":{},\"logs\":[]}",
                new String(VaultCrypto.decryptIndex(key, index), StandardCharsets.UTF_8));
        byte[] encrypted = VaultCrypto.encryptIndex(key, "hello from Android".getBytes(StandardCharsets.UTF_8));
        assertEquals("hello from Android", new String(VaultCrypto.decryptIndex(key, encrypted), StandardCharsets.UTF_8));
    }

    @Test public void fedoraBlobInteropAndTamperDetection() throws Exception {
        File blob = File.createTempFile("vault-test-", ".bin");
        try {
            Files.write(blob.toPath(), hex("4b564231000102030405060708090a0ba96b96991a8b40b3aa9c385d4d53b4e444b8d9af0eb99cffee03de63d9e892cee8ec8a14ce6215f57b64edc56a1c"));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            assertEquals(30, VaultCrypto.decryptBlob(expectedKey, id, blob, out));
            assertEquals("fedora and android compatible\n", out.toString("UTF-8"));
            byte[] altered = Files.readAllBytes(blob.toPath());
            altered[altered.length - 1] ^= 1;
            Files.write(blob.toPath(), altered);
            try { VaultCrypto.verifyBlob(expectedKey, id, blob); fail("Corrupt GCM tag accepted"); }
            catch (javax.crypto.AEADBadTagException expected) { }
        } finally { blob.delete(); }
    }

    @Test public void largeStreamingBlobRoundTrip() throws Exception {
        File blob = File.createTempFile("vault-large-", ".bin");
        byte[] source = new byte[2 * 1024 * 1024 + 13];
        new java.util.Random(1234).nextBytes(source);
        try {
            assertEquals(source.length, VaultCrypto.encryptBlob(expectedKey, id, new ByteArrayInputStream(source), blob));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            assertEquals(source.length, VaultCrypto.decryptBlob(expectedKey, id, blob, out));
            assertArrayEquals(source, out.toByteArray());
        } finally { blob.delete(); }
    }

    @Test public void tarArchiveStreamingRoundTrip() throws Exception {
        byte[] payload = new byte[1000];
        new java.util.Random(99).nextBytes(payload);
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        try (TarArchive.Writer tar = new TarArchive.Writer(raw)) {
            tar.add("manifest.json", new ByteArrayInputStream(payload), payload.length);
            tar.add("index.vlt", new ByteArrayInputStream(new byte[]{1, 2, 3}), 3);
        }
        java.util.List<String> names = new java.util.ArrayList<>();
        TarArchive.read(new ByteArrayInputStream(raw.toByteArray()), (name, size, data) -> {
            names.add(name);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[256]; int n;
            while ((n = data.read(buf)) != -1) out.write(buf, 0, n);
            assertEquals(size, out.size());
            if (name.equals("manifest.json")) assertArrayEquals(payload, out.toByteArray());
        });
        assertEquals(java.util.Arrays.asList("manifest.json", "index.vlt"), names);
    }
}
