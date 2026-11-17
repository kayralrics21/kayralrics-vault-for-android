package net.kayralrics.vault;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Small streaming USTAR reader/writer; rejects unsafe entry types and checksums. */
public final class TarArchive {
    private static final int BLOCK = 512;
    private TarArchive() { }

    public interface EntryConsumer { void accept(String name, long size, InputStream data) throws Exception; }

    public static final class Writer implements AutoCloseable {
        private final OutputStream out;
        private boolean closed;
        public Writer(OutputStream out) { this.out = out; }

        public void add(String name, InputStream data, long size) throws Exception {
            if (closed || name.length() > 100 || size < 0 || !name.matches("[a-zA-Z0-9._/\\-]+"))
                throw new IOException("Unsafe TAR entry");
            byte[] header = new byte[BLOCK];
            putString(header, 0, 100, name);
            putOct(header, 100, 8, 0600);
            putOct(header, 108, 8, 0);
            putOct(header, 116, 8, 0);
            putOct(header, 124, 12, size);
            putOct(header, 136, 12, System.currentTimeMillis() / 1000);
            Arrays.fill(header, 148, 156, (byte) ' ');
            header[156] = '0';
            putString(header, 257, 6, "ustar");
            header[262] = 0;
            putString(header, 263, 2, "00");
            long checksum = 0;
            for (byte b : header) checksum += (b & 0xff);
            putOct(header, 148, 8, checksum);
            out.write(header);
            byte[] buf = new byte[65536];
            long remaining = size;
            while (remaining > 0) {
                int n = data.read(buf, 0, (int) Math.min(buf.length, remaining));
                if (n < 0) throw new IOException("TAR source ended early");
                if (n == 0) continue;
                out.write(buf, 0, n);
                remaining -= n;
            }
            long pad = (BLOCK - size % BLOCK) % BLOCK;
            if (pad > 0) out.write(new byte[(int) pad]);
        }

        @Override public void close() throws IOException {
            if (closed) return;
            closed = true;
            out.write(new byte[BLOCK * 2]);
            out.flush();
        }
    }

    public static void read(InputStream in, EntryConsumer consumer) throws Exception {
        byte[] header = new byte[BLOCK];
        int entries = 0;
        while (true) {
            VaultCrypto.readFully(in, header);
            boolean zero = true;
            for (byte b : header) if (b != 0) { zero = false; break; }
            if (zero) {
                byte[] second = new byte[BLOCK];
                VaultCrypto.readFully(in, second);
                for (byte b : second) if (b != 0) throw new IOException("Invalid TAR end blocks");
                return;
            }
            if (++entries > 100000) throw new IOException("Too many TAR members");
            long savedChecksum = oct(header, 148, 8);
            long checksum = 0;
            for (int i = 0; i < BLOCK; i++) checksum += (i >= 148 && i < 156) ? 32 : (header[i] & 255);
            if (checksum != savedChecksum) throw new IOException("TAR checksum mismatch");
            long size = oct(header, 124, 12);
            if (size < 0) throw new IOException("Invalid TAR size");
            int type = header[156] & 255;
            String name = ascii(header, 0, 100);
            String prefix = ascii(header, 345, 155);
            if (!prefix.isEmpty()) name = prefix + "/" + name;
            Limited data = new Limited(in, size);
            if (type == 'x' || type == 'g') {
                // Python tarfile may emit PAX metadata; ignore metadata, not file contents.
            } else if (type == '0' || type == 0) {
                consumer.accept(name, size, data);
            } else {
                throw new IOException("Unsupported TAR member type");
            }
            byte[] buf = new byte[65536];
            while (data.remaining > 0) {
                int n = data.read(buf);
                if (n < 0) throw new IOException("Truncated TAR member");
            }
            skipFully(in, (BLOCK - size % BLOCK) % BLOCK);
        }
    }

    private static class Limited extends InputStream {
        private final InputStream in;
        long remaining;
        Limited(InputStream in, long size) { this.in = in; remaining = size; }
        @Override public int read() throws IOException {
            if (remaining == 0) return -1;
            int b = in.read();
            if (b < 0) throw new IOException("Truncated TAR member");
            remaining--;
            return b;
        }
        @Override public int read(byte[] b, int off, int len) throws IOException {
            if (remaining == 0) return -1;
            int n = in.read(b, off, (int) Math.min(len, remaining));
            if (n < 0) throw new IOException("Truncated TAR member");
            remaining -= n;
            return n;
        }
        @Override public void close() { /* Archive stream is owned by the TAR reader. */ }
    }

    private static void skipFully(InputStream in, long size) throws IOException {
        byte[] buffer = new byte[4096];
        while (size > 0) {
            int n = in.read(buffer, 0, (int) Math.min(buffer.length, size));
            if (n < 0) throw new IOException("Truncated TAR padding");
            size -= n;
        }
    }

    private static String ascii(byte[] bytes, int offset, int size) {
        int end = offset;
        while (end < offset + size && bytes[end] != 0) end++;
        return new String(bytes, offset, end - offset, StandardCharsets.US_ASCII);
    }

    private static void putString(byte[] b, int offset, int length, String value) {
        byte[] text = value.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(text, 0, b, offset, Math.min(length, text.length));
    }

    private static void putOct(byte[] b, int offset, int width, long value) throws IOException {
        String octal = Long.toOctalString(value);
        if (octal.length() > width - 1) throw new IOException("TAR size is too large");
        String padded = String.format(java.util.Locale.US, "%" + (width - 1) + "s", octal).replace(' ', '0');
        putString(b, offset, width - 1, padded);
        b[offset + width - 1] = 0;
    }

    private static long oct(byte[] data, int offset, int width) throws IOException {
        long number = 0;
        for (int i = offset; i < offset + width; i++) {
            int c = data[i] & 0xff;
            if (c == 0 || c == 32) continue;
            if (c < '0' || c > '7') throw new IOException("Invalid TAR numeric field");
            if (number > Long.MAX_VALUE / 8) throw new IOException("TAR numeric overflow");
            number = number * 8 + c - '0';
        }
        return number;
    }
}
