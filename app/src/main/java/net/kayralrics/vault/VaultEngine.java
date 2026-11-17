package net.kayralrics.vault;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Encrypted storage engine implementing the Fedora V1 disk/archive protocol. */
public final class VaultEngine {
    public static final int SCHEMA = 1;
    public static final int SCRYPT_N = 32768;
    public static final String FORMAT_ZIP = "zip", FORMAT_TAR = "tar", FORMAT_TGZ = "tar.gz";
    public static final class Item {
        public final String id, kind, name, details, date;
        public final long size;
        public Item(String id, String kind, String name, String details, String date, long size) {
            this.id = id; this.kind = kind; this.name = name; this.details = details; this.date = date; this.size = size;
        }
        public String key() { return kind + ":" + id; }
    }
    public static final class Verification {
        public int checked;
        public final List<String> errors = new ArrayList<>();
    }

    private final File root;
    private byte[] key;
    private JSONObject data;

    private VaultEngine(File folder, byte[] derived, JSONObject document) {
        root = folder; key = derived; data = document;
    }

    public static boolean exists(File folder) {
        return new File(folder, "manifest.json").isFile() && new File(folder, "index.vlt").isFile();
    }

    public static VaultEngine create(File folder, char[] password) throws Exception {
        if (password.length < 12) throw new IOException("Password must contain at least 12 characters.");
        if (folder.exists() && folder.list() != null && folder.list().length > 0)
            throw new IOException("The vault directory is not empty.");
        makeDir(folder);
        makeDir(new File(folder, "blobs"));
        makeDir(new File(folder, "snapshots"));
        byte[] salt = VaultCrypto.random(16);
        byte[] derived = VaultCrypto.derive(password, salt, SCRYPT_N);
        JSONObject manifest = new JSONObject();
        manifest.put("format", 1);
        manifest.put("kdf", "scrypt");
        manifest.put("n", SCRYPT_N);
        manifest.put("r", 8);
        manifest.put("p", 1);
        manifest.put("salt", toHex(salt));
        JSONObject document = new JSONObject();
        document.put("schema", 1);
        document.put("created_at", now());
        document.put("notes", new JSONObject());
        document.put("files", new JSONObject());
        document.put("logs", new JSONArray());
        VaultEngine engine = new VaultEngine(folder, derived, document);
        try {
            atomicWrite(new File(folder, "manifest.json"), manifest.toString().getBytes(StandardCharsets.UTF_8));
            engine.event("vault_created", "vault", "", "Encrypted vault created");
            engine.save(false);
            return engine;
        } catch (Exception ex) {
            Arrays.fill(derived, (byte) 0);
            throw ex;
        }
    }

    public static VaultEngine open(File folder, char[] password) throws Exception {
        JSONObject manifest = new JSONObject(new String(Files.readAllBytes(new File(folder, "manifest.json").toPath()), StandardCharsets.UTF_8));
        if (manifest.getInt("format") != 1 || !"scrypt".equals(manifest.getString("kdf"))
                || manifest.getInt("r") != 8 || manifest.getInt("p") != 1)
            throw new IOException("Unsupported vault manifest");
        byte[] salt = fromHex(manifest.getString("salt"));
        byte[] derived = VaultCrypto.derive(password, salt, manifest.getInt("n"));
        try {
            byte[] plaintext;
            try {
                plaintext = VaultCrypto.decryptIndex(derived, Files.readAllBytes(new File(folder, "index.vlt").toPath()));
            } catch (GeneralSecurityException ex) {
                throw new IOException("Incorrect password or corrupted encrypted index", ex);
            }
            JSONObject doc = new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
            Arrays.fill(plaintext, (byte) 0);
            if (doc.getInt("schema") != 1) throw new IOException("Unsupported vault schema");
            doc.getJSONObject("notes"); doc.getJSONObject("files"); doc.getJSONArray("logs");
            VaultEngine engine = new VaultEngine(folder, derived, doc);
            engine.event("vault_unlocked", "vault", "", "Vault unlocked locally on Android");
            engine.save(true);
            return engine;
        } catch (Exception ex) {
            Arrays.fill(derived, (byte) 0);
            throw ex;
        }
    }

    public synchronized void lock() throws Exception {
        if (key != null) {
            event("vault_locked", "vault", "", "Vault locked");
            save(true);
            Arrays.fill(key, (byte) 0);
            key = null;
            data = null;
        }
    }

    private void ensureOpen() throws IOException { if (key == null) throw new IOException("Vault is locked"); }
    private static String now() { return OffsetDateTime.now().truncatedTo(ChronoUnit.SECONDS).toString(); }
    private static String uuid() { return UUID.randomUUID().toString().replace("-", ""); }

    private void event(String action, String kind, String id, String detail) throws Exception {
        JSONObject entry = new JSONObject();
        entry.put("id", uuid());
        entry.put("at", now());
        entry.put("action", action);
        entry.put("kind", kind);
        entry.put("item_id", id);
        entry.put("detail", detail.length() > 300 ? detail.substring(0, 300) : detail);
        data.getJSONArray("logs").put(entry);
    }

    public synchronized void log(String action, String kind, String id, String detail) throws Exception {
        ensureOpen();
        event(action, kind, id, detail);
        save(true);
    }

    private void save(boolean snapshot) throws Exception {
        ensureOpen();
        File index = new File(root, "index.vlt");
        if (snapshot && index.exists()) {
            File directory = new File(root, "snapshots");
            makeDir(directory);
            String filename = "index-" + String.format(java.util.Locale.US, "%020d", System.currentTimeMillis() * 1000000L)
                    + "-" + uuid().substring(0, 8) + ".vlt";
            Files.copy(index.toPath(), new File(directory, filename).toPath());
            File[] snapshots = directory.listFiles((dir, name) -> name.startsWith("index-") && name.endsWith(".vlt"));
            if (snapshots != null && snapshots.length > 8) {
                Arrays.sort(snapshots, Comparator.comparing(File::getName));
                for (int i = 0; i < snapshots.length - 8; i++) snapshots[i].delete();
            }
        }
        byte[] encrypted = VaultCrypto.encryptIndex(key, data.toString().getBytes(StandardCharsets.UTF_8));
        atomicWrite(index, encrypted);
    }

    private static void atomicWrite(File dest, byte[] bytes) throws IOException {
        File temp = File.createTempFile(".pending-", ".tmp", dest.getParentFile());
        try (FileOutputStream out = new FileOutputStream(temp)) {
            out.write(bytes);
            out.getFD().sync();
        }
        try {
            Files.move(temp.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException ex) {
            Files.move(temp.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } finally {
            temp.delete();
        }
    }

    private static void makeDir(File folder) throws IOException {
        if (!folder.isDirectory() && !folder.mkdirs()) throw new IOException("Cannot create private vault folder");
    }
    private static String toHex(byte[] bytes) {
        StringBuilder b = new StringBuilder();
        for (byte v : bytes) b.append(String.format(java.util.Locale.US, "%02x", v & 255));
        return b.toString();
    }
    private static byte[] fromHex(String s) throws IOException {
        if (!s.matches("[0-9a-fA-F]{32}")) throw new IOException("Invalid vault salt");
        byte[] bytes = new byte[s.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }
    private static File blob(File root, String id) throws IOException {
        if (!id.matches("[0-9a-f]{32}")) throw new IOException("Invalid encrypted file identifier");
        return new File(new File(root, "blobs"), id + ".bin");
    }
    private static String path(String p) throws IOException {
        if (p == null || p.isEmpty() || p.startsWith("/") || p.contains("\\") || p.indexOf('\u0000') >= 0 || p.split("/", -1)[0].contains(":"))
            throw new IOException("Unsafe relative path");
        for (String part : p.split("/", -1)) if (part.isEmpty() || part.equals(".") || part.equals(".."))
            throw new IOException("Unsafe relative path");
        return p;
    }

    public synchronized List<Item> items(String filter) throws Exception {
        ensureOpen();
        List<Item> out = new ArrayList<>();
        boolean trashed = "trash".equals(filter);
        if (!"files".equals(filter)) {
            JSONObject notes = data.getJSONObject("notes");
            for (java.util.Iterator<String> it = notes.keys(); it.hasNext();) {
                String id = it.next(); JSONObject note = notes.getJSONObject(id);
                if ((!note.isNull("trashed_at")) != trashed) continue;
                out.add(new Item(id, "note", note.getString("title"),
                        "NOTE  •  " + note.getString("updated_at"), note.getString("updated_at"), 0));
            }
        }
        if (!"notes".equals(filter)) {
            JSONObject files = data.getJSONObject("files");
            for (java.util.Iterator<String> it = files.keys(); it.hasNext();) {
                String id = it.next(); JSONObject file = files.getJSONObject(id);
                if ((!file.isNull("trashed_at")) != trashed) continue;
                out.add(new Item(id, "file", file.getString("path"),
                        "FILE  •  " + file.optLong("size") + " B  •  " + file.getString("added_at"),
                        file.getString("added_at"), file.getLong("size")));
            }
        }
        out.sort((a, b) -> b.date.compareTo(a.date));
        return out;
    }

    public synchronized JSONObject note(String id) throws Exception {
        ensureOpen();
        return new JSONObject(data.getJSONObject("notes").getJSONObject(id).toString());
    }

    public synchronized JSONObject file(String id) throws Exception {
        ensureOpen();
        return new JSONObject(data.getJSONObject("files").getJSONObject(id).toString());
    }

    public synchronized String addNote(String title) throws Exception {
        ensureOpen();
        JSONObject before = new JSONObject(data.toString());
        String id = uuid(), stamp = now();
        try {
            JSONObject note = new JSONObject();
            note.put("id", id); note.put("title", title); note.put("body", "");
            note.put("created_at", stamp); note.put("updated_at", stamp); note.put("trashed_at", JSONObject.NULL);
            data.getJSONObject("notes").put(id, note);
            event("note_created", "note", id, title);
            save(true);
            return id;
        } catch (Exception ex) { data = before; throw ex; }
    }

    public synchronized boolean updateNote(String id, String title, String body) throws Exception {
        ensureOpen();
        JSONObject note = data.getJSONObject("notes").getJSONObject(id);
        if (!note.isNull("trashed_at")) throw new IOException("Cannot edit a trashed note");
        title = title.trim();
        if (title.isEmpty()) title = "Untitled note";
        if (title.length() > 220) throw new IOException("Note title exceeds 220 characters");
        if (title.equals(note.getString("title")) && body.equals(note.getString("body"))) return false;
        JSONObject before = new JSONObject(data.toString());
        try {
            note.put("title", title); note.put("body", body); note.put("updated_at", now());
            event("note_updated", "note", id, title);
            save(true);
            return true;
        } catch (Exception ex) { data = before; throw ex; }
    }

    public synchronized String importFile(InputStream source, String name, String relativePath) throws Exception {
        ensureOpen();
        path(relativePath);
        String id = uuid();
        File pending = File.createTempFile(".import-", ".bin", new File(root, "blobs"));
        File dest = blob(root, id);
        JSONObject before = new JSONObject(data.toString());
        try {
            long length = VaultCrypto.encryptBlob(key, id, source, pending);
            Files.move(pending.toPath(), dest.toPath(), StandardCopyOption.ATOMIC_MOVE);
            JSONObject item = new JSONObject();
            item.put("id", id); item.put("name", name); item.put("path", relativePath);
            item.put("size", length); item.put("added_at", now()); item.put("trashed_at", JSONObject.NULL);
            data.getJSONObject("files").put(id, item);
            event("file_imported", "file", id, relativePath);
            save(true);
            return id;
        } catch (Exception ex) {
            data = before;
            dest.delete();
            throw ex;
        } finally { pending.delete(); }
    }

    /** Batch operations validate all selected IDs before committing a single encrypted index. */
    public synchronized int batch(String command, List<String> selected) throws Exception {
        ensureOpen();
        if (!Arrays.asList("trash", "restore", "purge").contains(command)) throw new IOException("Unsupported operation");
        JSONObject before = new JSONObject(data.toString());
        List<String> toRemove = new ArrayList<>();
        Set<String> unique = new HashSet<>(selected);
        // Phase 1: validate EVERY selected object before changing anything.
        for (String key : unique) {
            String[] parts = key.split(":", -1);
            if (parts.length != 2 || !parts[1].matches("[0-9a-f]{32}")
                    || !(parts[0].equals("note") || parts[0].equals("file")))
                throw new IOException("Invalid selected item");
            JSONObject collection = data.getJSONObject(parts[0].equals("note") ? "notes" : "files");
            JSONObject item = collection.optJSONObject(parts[1]);
            if (item == null) throw new IOException("Selection changed: refresh and retry");
            if (command.equals("purge") && item.isNull("trashed_at"))
                throw new IOException("Move items to Trash before permanent deletion");
        }
        int count = 0;
        String verb = command.equals("trash") ? "trashed" : command.equals("restore") ? "restored" : "purged";
        try {
            for (String s : unique) {
                String[] parts = s.split(":", -1);
                JSONObject collection = data.getJSONObject(parts[0].equals("note") ? "notes" : "files");
                JSONObject item = collection.getJSONObject(parts[1]);
                boolean isTrashed = !item.isNull("trashed_at");
                if (command.equals("trash") && isTrashed) continue;
                if (command.equals("restore") && !isTrashed) continue;
                String detail = item.optString("title", item.optString("path", ""));
                if (command.equals("trash")) item.put("trashed_at", now());
                else if (command.equals("restore")) item.put("trashed_at", JSONObject.NULL);
                else {
                    collection.remove(parts[1]);
                    if (parts[0].equals("file")) toRemove.add(parts[1]);
                }
                event(parts[0] + "_" + verb, parts[0], parts[1], detail);
                count++;
            }
            if (count > 1) event("batch_" + verb, "vault", "", count + " items");
            if (count > 0) save(true);
        } catch (Exception ex) {
            data = before;
            throw ex;
        }
        for (String id : toRemove) blob(root, id).delete();
        return count;
    }

    public synchronized List<JSONObject> logs(String search) throws Exception {
        ensureOpen();
        List<JSONObject> list = new ArrayList<>();
        JSONArray logs = data.getJSONArray("logs");
        for (int i = logs.length() - 1; i >= 0; i--) {
            JSONObject row = logs.getJSONObject(i);
            if (search.isEmpty() || row.toString().toLowerCase(java.util.Locale.ROOT)
                    .contains(search.toLowerCase(java.util.Locale.ROOT))) list.add(row);
        }
        return list;
    }

    public synchronized String stats() throws Exception {
        ensureOpen();
        int notes = items("notes").size(), files = items("files").size(), trash = items("trash").size();
        long size = 0;
        for (Item item : items("files")) size += item.size;
        return notes + " notes   •   " + files + " files   •   " + trash + " in trash\n"
                + size + " bytes of active files   •   " + data.getJSONArray("logs").length() + " log entries";
    }

    public synchronized long verifyFile(String id) throws Exception {
        ensureOpen();
        long size = VaultCrypto.verifyBlob(key, id, blob(root, id));
        if (size != data.getJSONObject("files").getJSONObject(id).getLong("size"))
            throw new IOException("File size mismatch");
        return size;
    }

    public synchronized byte[] preview(String id, long max) throws Exception {
        ensureOpen();
        JSONObject item = data.getJSONObject("files").getJSONObject(id);
        if (item.getLong("size") > max) throw new IOException("Preview limit exceeded");
        return VaultCrypto.previewBlob(key, id, blob(root, id), max);
    }

    public synchronized void exportFile(String id, OutputStream output) throws Exception {
        ensureOpen();
        // Authentication pass before streaming plaintext to a public SAF destination.
        verifyFile(id);
        long decrypted = VaultCrypto.decryptBlob(key, id, blob(root, id), output);
        if (decrypted != data.getJSONObject("files").getJSONObject(id).getLong("size"))
            throw new IOException("File size changed during export");
        event("file_exported_plaintext", "file", id, data.getJSONObject("files").getJSONObject(id).getString("path"));
        save(true);
    }

    public synchronized Verification verifyAll() throws Exception {
        ensureOpen();
        Verification result = new Verification();
        JSONObject files = data.getJSONObject("files");
        for (java.util.Iterator<String> it = files.keys(); it.hasNext();) {
            String id = it.next();
            result.checked++;
            try { verifyFile(id); }
            catch (Exception e) { result.errors.add(files.getJSONObject(id).getString("path") + ": " + e.getMessage()); }
        }
        event("integrity_verified", "vault", "", result.checked + " files, " + result.errors.size() + " errors");
        save(true);
        return result;
    }

    private interface EntryWriter { void write(String name, File file) throws Exception; }

    private synchronized void backupEntries(EntryWriter writer) throws Exception {
        writer.write("manifest.json", new File(root, "manifest.json"));
        writer.write("index.vlt", new File(root, "index.vlt"));
        JSONObject files = data.getJSONObject("files");
        for (java.util.Iterator<String> it = files.keys(); it.hasNext();) {
            String id = it.next();
            File f = blob(root, id);
            if (!f.isFile()) throw new IOException("Encrypted file missing: " + id);
            writer.write("blobs/" + id + ".bin", f);
        }
    }

    public synchronized void encryptedBackup(OutputStream destination, String format) throws Exception {
        ensureOpen();
        if (format.equals(FORMAT_ZIP)) {
            ZipOutputStream zip = new ZipOutputStream(destination);
            zip.setLevel(0); // Encrypted data is already incompressible.
            backupEntries((name, file) -> {
                zip.putNextEntry(new ZipEntry(name));
                try (InputStream src = new FileInputStream(file)) { copy(src, zip); }
                zip.closeEntry();
            });
            zip.finish(); zip.flush();
        } else if (format.equals(FORMAT_TAR) || format.equals(FORMAT_TGZ)) {
            OutputStream out = format.equals(FORMAT_TGZ) ? new GZIPOutputStream(destination) : destination;
            try (TarArchive.Writer tar = new TarArchive.Writer(out)) {
                backupEntries((name, file) -> {
                    try (InputStream src = new FileInputStream(file)) { tar.add(name, src, file.length()); }
                });
            }
            if (out instanceof GZIPOutputStream) ((GZIPOutputStream) out).finish();
        } else throw new IOException("Unsupported backup format");
        event("encrypted_backup_exported", "vault", "", format + " backup exported on Android");
        save(true);
    }

    public synchronized void readableZip(OutputStream destination) throws Exception {
        ensureOpen();
        ZipOutputStream zip = new ZipOutputStream(destination);
        for (Item note : items("notes")) {
            String title = note.name.replaceAll("[^\\p{L}\\p{N}._ -]", "_").trim();
            if (title.length() > 90) title = title.substring(0, 90);
            if (title.isEmpty()) title = "untitled";
            zip.putNextEntry(new ZipEntry("notes/" + title + "-" + note.id.substring(0, 8) + ".txt"));
            zip.write(data.getJSONObject("notes").getJSONObject(note.id).getString("body").getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        Set<String> used = new HashSet<>();
        for (Item file : items("files")) {
            String name = "files/" + path(data.getJSONObject("files").getJSONObject(file.id).getString("path"));
            if (!used.add(name)) name = "files/duplicates/" + file.id.substring(0, 8) + "/"
                    + path(data.getJSONObject("files").getJSONObject(file.id).getString("name"));
            verifyFile(file.id);
            zip.putNextEntry(new ZipEntry(name));
            long len = VaultCrypto.decryptBlob(key, file.id, blob(root, file.id), zip);
            if (len != file.size) throw new IOException("Exported file size mismatch");
            zip.closeEntry();
        }
        zip.putNextEntry(new ZipEntry("logs.json"));
        zip.write(data.getJSONArray("logs").toString(2).getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
        zip.putNextEntry(new ZipEntry("README.txt"));
        zip.write("WARNING: This ZIP contains UNENCRYPTED notes, files, and logs.\n".getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
        zip.finish(); zip.flush();
        event("readable_backup_exported", "vault", "", "UNENCRYPTED ZIP exported by user");
        save(true);
    }

    public static String detectFormat(String filename) throws IOException {
        String lower = filename.toLowerCase(java.util.Locale.ROOT);
        if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) return FORMAT_TGZ;
        if (lower.endsWith(".tar")) return FORMAT_TAR;
        if (lower.endsWith(".zip")) return FORMAT_ZIP;
        throw new IOException("Select a .zip, .tar.gz, .tgz, or .tar backup");
    }

    private static void acceptBackupMember(File target, String name, InputStream input, Set<String> seen) throws Exception {
        boolean allowed = name.equals("manifest.json") || name.equals("index.vlt")
                || name.matches("blobs/[0-9a-f]{32}\\.bin");
        if (!allowed || !seen.add(name)) throw new IOException("Unsafe or duplicate backup member: " + name);
        File out = new File(target, name);
        if (!out.getCanonicalPath().startsWith(target.getCanonicalPath() + File.separator))
            throw new IOException("Unsafe backup path");
        try (FileOutputStream dest = new FileOutputStream(out)) {
            copy(input, dest);
            dest.getFD().sync();
        }
    }

    /** Restore ciphertext into a staging folder, authenticate password, then swap directories. */
    public static void restoreBackup(File active, InputStream source, String name, char[] password) throws Exception {
        File parent = active.getParentFile();
        File pending = new File(parent, "vault-restore-staging");
        File previous = new File(parent, "vault-previous");
        if (previous.exists()) throw new IOException("A previous vault is already preserved. Restore it or export it before another replacement.");
        if (pending.exists()) deleteTree(pending);
        makeDir(pending);
        makeDir(new File(pending, "blobs"));
        makeDir(new File(pending, "snapshots"));
        boolean swapped = false;
        try {
            Set<String> seen = new HashSet<>();
            String format = detectFormat(name);
            if (format.equals(FORMAT_ZIP)) {
                try (ZipInputStream zip = new ZipInputStream(source)) {
                    ZipEntry e;
                    while ((e = zip.getNextEntry()) != null) {
                        if (e.isDirectory()) throw new IOException("Directory in encrypted backup");
                        acceptBackupMember(pending, e.getName(), zip, seen);
                        zip.closeEntry();
                    }
                }
            } else {
                InputStream in = format.equals(FORMAT_TGZ) ? new GZIPInputStream(source) : source;
                TarArchive.read(in, (member, bytes, body) -> acceptBackupMember(pending, member, body, seen));
            }
            if (!seen.contains("manifest.json") || !seen.contains("index.vlt"))
                throw new IOException("Backup is incomplete");
            VaultEngine test = open(pending, password);
            try {
                // Test that all files referenced by the index are actually present.
                JSONObject files = test.data.getJSONObject("files");
                for (java.util.Iterator<String> it = files.keys(); it.hasNext();) {
                    String id = it.next();
                    if (!blob(pending, id).isFile()) throw new IOException("Missing file in backup: " + id);
                }
                Verification verification = test.verifyAll();
                if (!verification.errors.isEmpty()) throw new IOException("Backup contains damaged encrypted files: "
                        + verification.errors.get(0));
            } finally { test.lock(); }
            if (active.exists()) {
                if (!active.renameTo(previous)) throw new IOException("Could not preserve the existing vault");
            }
            try {
                if (!pending.renameTo(active)) throw new IOException("Could not activate restored vault");
                swapped = true;
            } finally {
                if (!swapped && previous.exists()) previous.renameTo(active);
            }
        } finally { if (!swapped) deleteTree(pending); }
    }

    public static void swapPrevious(File active) throws Exception {
        File previous = new File(active.getParentFile(), "vault-previous");
        File temp = new File(active.getParentFile(), "vault-swap-tmp");
        if (!previous.isDirectory() || temp.exists()) throw new IOException("No previous vault available to recover");
        if (!active.renameTo(temp)) throw new IOException("Could not stage current vault");
        if (!previous.renameTo(active)) { temp.renameTo(active); throw new IOException("Could not switch previous vault"); }
        if (!temp.renameTo(previous)) throw new IOException("Switched vault, but previous swap could not be finalized");
    }

    public static void deleteTree(File f) throws IOException {
        if (!f.exists()) return;
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children == null) throw new IOException("Could not read folder");
            for (File child : children) deleteTree(child);
        }
        if (!f.delete()) throw new IOException("Could not remove temporary file: " + f.getName());
    }

    private static void copy(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[65536];
        int n;
        while ((n = input.read(buffer)) != -1) if (n > 0) output.write(buffer, 0, n);
    }
}
