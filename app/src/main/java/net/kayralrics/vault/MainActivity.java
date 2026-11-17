package net.kayralrics.vault;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.ColorStateList;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.WindowInsets;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Android UI: offline-only black/red vault with a SAF-based import/export workflow. */
public class MainActivity extends Activity {
    private static final int BLACK = Color.BLACK, RED = Color.RED, WHITE = Color.WHITE;
    private static final int SUBTLE = 0xff929292, CARD = 0xff0b0b0b, BORDER = 0xff303030;
    private static final long IDLE_MS = 15 * 60 * 1000L;
    private static final int PICK_FILES = 101, PICK_TREE = 102, SAVE_FILE = 103;
    private static final int SAVE_BACKUP = 104, SAVE_READABLE = 105, PICK_BACKUP = 106;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Set<String> selected = new HashSet<>();
    private File vaultFolder;
    private VaultEngine vault;
    private LinearLayout root, page;
    private String screen = "notes", editingId, exportId, backupFormat = "zip";
    private EditText noteTitle, noteBody;
    private boolean busy;
    private long lastTouch;
    private Runnable autosave;
    private Runnable idleWatch;
    private TextView selectedCount;
    private List<VaultEngine.Item> visibleItems = new ArrayList<>();
    private BaseAdapter listAdapter;

    private interface Work { void run() throws Exception; }

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setStatusBarColor(BLACK);
        getWindow().setNavigationBarColor(BLACK);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        vaultFolder = new File(getFilesDir(), "vault");
        lastTouch = System.currentTimeMillis();
        idleWatch = new Runnable() {
            @Override public void run() {
                if (vault != null && !busy && timedOut()) { lockVault(); return; }
                handler.postDelayed(this, 60000);
            }
        };
        handler.postDelayed(idleWatch, 60000);
        showLogin();
    }

    private boolean timedOut() { return System.currentTimeMillis() - lastTouch > IDLE_MS; }
    @Override public void onUserInteraction() { super.onUserInteraction(); lastTouch = System.currentTimeMillis(); }
    @Override protected void onResume() {
        super.onResume();
        if (vault != null && !busy && timedOut()) lockVault();
    }
    @Override protected void onPause() {
        if (vault != null && "editor".equals(screen) && !busy) saveEditor(false);
        super.onPause();
    }
    @Override public void onConfigurationChanged(Configuration config) {
        super.onConfigurationChanged(config);
        if (vault == null) showLogin();
        else if ("editor".equals(screen)) { saveEditor(false); showEditor(editingId); }
        else showScreen(screen);
    }
    @Override protected void onDestroy() {
        handler.removeCallbacks(idleWatch);
        if (autosave != null) handler.removeCallbacks(autosave);
        if (vault != null && !busy) try { vault.lock(); } catch (Exception ignored) { }
        worker.shutdown();
        super.onDestroy();
    }

    private int dp(float n) { return (int) (n * getResources().getDisplayMetrics().density + 0.5f); }
    private LinearLayout vertical() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.VERTICAL); return l; }
    private LinearLayout horizontal() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.HORIZONTAL); l.setGravity(Gravity.CENTER_VERTICAL); return l; }
    private GradientDrawable panel(int fill, int stroke, int radius) {
        GradientDrawable d = new GradientDrawable(); d.setColor(fill); d.setCornerRadius(dp(radius));
        if (stroke != 0) d.setStroke(dp(1), stroke); return d;
    }
    private TextView text(String content, int size, int color, boolean bold) {
        TextView v = new TextView(this); v.setText(content); v.setTextColor(color); v.setTextSize(size);
        if (bold) v.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        v.setGravity(Gravity.CENTER_VERTICAL); return v;
    }
    private EditText input(String hint, String text, boolean multiline) {
        EditText e = new EditText(this);
        e.setTextColor(WHITE); e.setHintTextColor(SUBTLE); e.setTextSize(15);
        e.setHint(hint); e.setText(text); e.setPadding(dp(14), dp(10), dp(14), dp(10));
        e.setBackground(panel(CARD, BORDER, 5));
        e.setSingleLine(!multiline);
        e.setInputType(multiline ? InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES : InputType.TYPE_CLASS_TEXT);
        if (multiline) e.setGravity(Gravity.TOP); return e;
    }
    private EditText passwordInput(String hint) {
        EditText e = input(hint, "", false);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        return e;
    }
    private Button button(String title, Runnable onClick, boolean primary) {
        Button b = new Button(this);
        b.setText(title); b.setAllCaps(false); b.setTextSize(12);
        b.setTextColor(primary ? WHITE : RED);
        b.setBackground(panel(primary ? RED : BLACK, RED, 4));
        b.setPadding(dp(12), dp(2), dp(12), dp(2));
        b.setMinHeight(dp(43)); b.setMinimumHeight(dp(43));
        b.setOnClickListener(view -> { lastTouch = System.currentTimeMillis(); if (!busy) onClick.run(); });
        return b;
    }
    private void addSpace(LinearLayout into, int height) {
        View v = new View(this); into.addView(v, new LinearLayout.LayoutParams(1, dp(height)));
    }
    private void add(LinearLayout into, View child, int height) {
        into.addView(child, new LinearLayout.LayoutParams(-1, height < 0 ? height : dp(height)));
    }
    private void marginButton(LinearLayout into, Button b) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, dp(43));
        lp.topMargin = dp(8); into.addView(b, lp);
    }
    private void installRoot(boolean nav) {
        root = vertical(); root.setBackgroundColor(BLACK);
        if (Build.VERSION.SDK_INT >= 30) {
            root.setOnApplyWindowInsetsListener((v, insets) -> {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                v.setPadding(0, bars.top, 0, bars.bottom); return insets;
            });
        } else {
            root.setFitsSystemWindows(true);
        }
        setContentView(root);
        LinearLayout header = vertical();
        header.setPadding(dp(20), dp(14), dp(20), dp(13));
        TextView title = text("KAYRALRICS  /  VAULT", 23, RED, true);
        header.addView(title);
        header.addView(text("AES-256-GCM   •   LOCAL-ONLY   •   ANDROID", 10, SUBTLE, false));
        root.addView(header);
        View line = new View(this); line.setBackgroundColor(RED);
        root.addView(line, new LinearLayout.LayoutParams(-1, dp(1)));
        if (nav) {
            LinearLayout bar = horizontal();
            bar.setPadding(dp(10), dp(8), dp(10), dp(8));
            for (String section : new String[]{"notes", "files", "trash", "logs", "settings"}) {
                Button b = button(section.toUpperCase(Locale.ROOT), () -> {
                    if ("editor".equals(screen)) saveEditor(false);
                    showScreen(section);
                }, screen.equals(section));
                LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-2, dp(42));
                p.rightMargin = dp(7); bar.addView(b, p);
            }
            HorizontalNav navScroll = new HorizontalNav(this);
            navScroll.addView(bar); root.addView(navScroll);
        }
        page = vertical(); page.setPadding(dp(15), dp(12), dp(15), dp(8));
        root.addView(page, new LinearLayout.LayoutParams(-1, 0, 1));
        TextView footer = text("kayralrics.net", 11, SUBTLE, false);
        footer.setGravity(Gravity.CENTER);
        add(root, footer, 27);
    }
    private static class HorizontalNav extends android.widget.HorizontalScrollView {
        HorizontalNav(Activity a) { super(a); setHorizontalScrollBarEnabled(false); }
    }
    private ScrollView scroll(LinearLayout into) {
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(false);
        into.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1)); return scroll;
    }
    private LinearLayout scrollColumn(LinearLayout into) {
        ScrollView sv = scroll(into);
        LinearLayout col = vertical(); col.setPadding(dp(4), dp(2), dp(4), dp(20));
        sv.addView(col); return col;
    }
    private void heading(String text) {
        TextView heading = text(text, 21, WHITE, true); add(page, heading, 42);
    }
    private void info(LinearLayout col, String text) {
        TextView t = text(text, 13, SUBTLE, false); t.setPadding(dp(2), dp(6), dp(2), dp(6)); add(col, t, -2);
    }
    private void message(String title, String body) {
        new AlertDialog.Builder(this).setTitle(title).setMessage(body).setPositiveButton("OK", null).show();
    }
    private void error(Throwable ex) {
        String msg = ex.getMessage();
        if (msg == null || msg.isEmpty()) msg = ex.getClass().getSimpleName();
        message("Operation failed", msg);
    }
    private void async(String task, Work operation, Runnable onSuccess) {
        if (busy) return;
        busy = true;
        installRoot(false);
        heading(task.toUpperCase(Locale.ROOT));
        TextView status = text("Working locally. Keep this app open until the operation completes.", 14, SUBTLE, false);
        add(page, status, -2);
        worker.execute(() -> {
            try {
                operation.run();
                runOnUiThread(() -> {
                    busy = false; lastTouch = System.currentTimeMillis();
                    try { onSuccess.run(); } catch (Exception e) { error(e); showLogin(); }
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    busy = false; lastTouch = System.currentTimeMillis();
                    if (vault != null) showScreen(screen); else showLogin();
                    error(e);
                });
            }
        });
    }

    private void showLogin() {
        screen = "login"; selected.clear(); editingId = null;
        installRoot(false);
        LinearLayout col = scrollColumn(page);
        addSpace(col, 22);
        TextView welcome = text(VaultEngine.exists(vaultFolder) ? "UNLOCK YOUR VAULT" : "CREATE ENCRYPTED VAULT", 24, RED, true);
        add(col, welcome, -2); addSpace(col, 12);
        info(col, "Private storage on this device. No accounts, server, internet permissions, or external sync.");
        addSpace(col, 12);
        EditText pw = passwordInput("Master password (12+ characters)");
        add(col, pw, 55); addSpace(col, 8);
        EditText confirm = null;
        if (!VaultEngine.exists(vaultFolder)) {
            confirm = passwordInput("Confirm master password"); add(col, confirm, 55);
            info(col, "Your password cannot be recovered. Store it safely, and keep external encrypted backups.");
        }
        final EditText second = confirm;
        marginButton(col, button(VaultEngine.exists(vaultFolder) ? "UNLOCK" : "CREATE VAULT", () -> {
            char[] pass = pw.getText().toString().toCharArray();
            if (!VaultEngine.exists(vaultFolder)) {
                if (pass.length < 12) { message("Password required", "Use at least 12 characters."); return; }
                if (second == null || !Arrays.equals(pass, second.getText().toString().toCharArray())) {
                    message("Password mismatch", "Both passwords must match."); return;
                }
            }
            boolean existing = VaultEngine.exists(vaultFolder);
            async(existing ? "Unlocking encrypted vault" : "Creating encrypted vault", () -> {
                try { vault = existing ? VaultEngine.open(vaultFolder, pass) : VaultEngine.create(vaultFolder, pass); }
                finally { Arrays.fill(pass, '\0'); }
            }, () -> showScreen("notes"));
        }, true));
        addSpace(col, 15);
        marginButton(col, button("RESTORE ENCRYPTED BACKUP", () -> chooseBackup(), false));
        if (new File(getFilesDir(), "vault-previous").exists()) {
            marginButton(col, button("SWITCH TO PREVIOUS LOCAL VAULT", this::confirmSwitchPrevious, false));
            marginButton(col, button("DISCARD PREVIOUS VAULT", this::confirmDiscardPrevious, false));
        }
    }

    private void showScreen(String next) {
        if (vault == null) { showLogin(); return; }
        if ("editor".equals(screen) && !"editor".equals(next)) saveEditor(false);
        screen = next; selected.clear(); editingId = null;
        installRoot(true);
        try {
            switch (next) {
                case "notes": records("notes"); break;
                case "files": records("files"); break;
                case "trash": records("trash"); break;
                case "logs": logsScreen(); break;
                case "settings": settingsScreen(); break;
                default: records("notes"); break;
            }
            if (!"logs".equals(next)) vault.log("navigation", "ui", "", next);
        } catch (Exception e) { error(e); }
    }

    private void records(String kind) throws Exception {
        heading(kind.equals("trash") ? "TRASH" : kind.toUpperCase(Locale.ROOT));
        LinearLayout toolbar = horizontal();
        Button primary;
        if (kind.equals("notes")) primary = button("+ NEW NOTE", () -> {
            try { showEditor(vault.addNote("Untitled note")); } catch (Exception e) { error(e); }
        }, true);
        else if (kind.equals("files")) primary = button("+ ADD FILES", this::pickFiles, true);
        else primary = button("RESTORE", () -> batch("restore"), true);
        toolbar.addView(primary, new LinearLayout.LayoutParams(-2, dp(42)));
        if (kind.equals("files")) {
            toolbar.addView(spaceWidth(7));
            toolbar.addView(button("+ FOLDER", this::pickFolder, false));
        }
        toolbar.addView(spaceWidth(7));
        toolbar.addView(button("SELECT ALL", this::selectAll, false));
        HorizontalNav scroll = new HorizontalNav(this); scroll.addView(toolbar); add(page, scroll, 49);
        LinearLayout actions = horizontal();
        selectedCount = text("0 SELECTED", 12, SUBTLE, false);
        actions.addView(selectedCount, new LinearLayout.LayoutParams(0, dp(40), 1));
        actions.addView(button("CLEAR", () -> { selected.clear(); updateSelection(); }, false));
        actions.addView(spaceWidth(7));
        actions.addView(button(kind.equals("trash") ? "DELETE PERMANENTLY" : "TRASH SELECTED",
                () -> batch(kind.equals("trash") ? "purge" : "trash"), true));
        add(page, actions, 52);
        EditText search = input("Search " + kind + "...", "", false);
        add(page, search, 47); addSpace(page, 7);
        ListView list = new ListView(this);
        list.setDividerHeight(dp(7)); list.setDivider(null); list.setCacheColorHint(BLACK);
        addList(list);
        List<VaultEngine.Item> all = vault.items(kind);
        visibleItems = new ArrayList<>(all);
        listAdapter = new BaseAdapter() {
            @Override public int getCount() { return visibleItems.size(); }
            @Override public Object getItem(int pos) { return visibleItems.get(pos); }
            @Override public long getItemId(int pos) { return pos; }
            @Override public View getView(int pos, View convertView, ViewGroup parent) {
                VaultEngine.Item item = visibleItems.get(pos);
                LinearLayout row = horizontal();
                row.setPadding(dp(9), dp(7), dp(9), dp(7));
                row.setBackground(panel(CARD, selected.contains(item.key()) ? RED : BORDER, 5));
                CheckBox cb = new CheckBox(MainActivity.this); cb.setButtonTintList(ColorStateList.valueOf(RED));
                cb.setChecked(selected.contains(item.key()));
                cb.setOnCheckedChangeListener((view, isChecked) -> {
                    if (isChecked) selected.add(item.key()); else selected.remove(item.key());
                    updateSelection();
                });
                row.addView(cb);
                LinearLayout labels = vertical();
                TextView name = text(item.name, 15, WHITE, true);
                name.setMaxLines(2); name.setEllipsize(android.text.TextUtils.TruncateAt.END);
                labels.addView(name);
                TextView sub = text(item.details, 11, SUBTLE, false);
                sub.setMaxLines(2); sub.setEllipsize(android.text.TextUtils.TruncateAt.END);
                labels.addView(sub);
                row.addView(labels, new LinearLayout.LayoutParams(0, -2, 1));
                row.setOnLongClickListener(v -> {
                    if (!selected.add(item.key())) selected.remove(item.key());
                    updateSelection(); return true;
                });
                row.setOnClickListener(v -> {
                    if (kind.equals("notes")) showEditor(item.id);
                    else if (kind.equals("files")) fileDetails(item);
                    else {
                        if (!selected.add(item.key())) selected.remove(item.key());
                        updateSelection();
                    }
                });
                return row;
            }
        };
        list.setAdapter(listAdapter);
        search.addTextChangedListener(new SimpleWatcher() {
            @Override public void afterTextChanged(Editable s) {
                String query = s.toString().toLowerCase(Locale.ROOT);
                visibleItems = new ArrayList<>();
                for (VaultEngine.Item item : all) if (item.name.toLowerCase(Locale.ROOT).contains(query)
                        || item.details.toLowerCase(Locale.ROOT).contains(query)) visibleItems.add(item);
                listAdapter.notifyDataSetChanged();
            }
        });
        if (all.isEmpty()) info(page, kind.equals("trash") ? "Trash is empty." : "No items yet.");
    }

    private View spaceWidth(int n) {
        View v = new View(this); v.setLayoutParams(new LinearLayout.LayoutParams(dp(n), 1)); return v;
    }
    private void addList(ListView list) { page.addView(list, new LinearLayout.LayoutParams(-1, 0, 1)); }
    private void updateSelection() {
        if (selectedCount != null) selectedCount.setText(selected.size() + " SELECTED");
        if (listAdapter != null) listAdapter.notifyDataSetChanged();
    }
    private void selectAll() { for (VaultEngine.Item item : visibleItems) selected.add(item.key()); updateSelection(); }

    private void batch(String command) {
        if (selected.isEmpty()) { message("Nothing selected", "Use checkboxes, long press, or SELECT ALL first."); return; }
        int total = selected.size();
        String prompt = command.equals("purge")
                ? "Permanently remove " + total + " selected items? This cannot be undone from the active vault."
                : (command.equals("restore") ? "Restore " : "Move to Trash ") + total + " selected items?";
        new AlertDialog.Builder(this).setTitle(command.equals("purge") ? "PERMANENT DELETE" : "BATCH ACTION")
                .setMessage(prompt).setNegativeButton("CANCEL", null)
                .setPositiveButton(command.equals("purge") ? "DELETE PERMANENTLY" : "CONTINUE", (d, w) -> {
                    try {
                        int count = vault.batch(command, new ArrayList<>(selected));
                        showScreen(screen);
                        message("Completed", count + " items processed.");
                    } catch (Exception e) { error(e); }
                }).show();
    }

    private void showEditor(String id) {
        try {
            JSONObject note = vault.note(id);
            screen = "editor"; editingId = id; selected.clear();
            installRoot(false);
            LinearLayout buttons = horizontal();
            buttons.addView(button("← NOTES", () -> { saveEditor(false); showScreen("notes"); }, false));
            buttons.addView(spaceWidth(9));
            buttons.addView(button("SAVE NOW", () -> saveEditor(true), true));
            buttons.addView(spaceWidth(9));
            buttons.addView(button("TRASH", () -> new AlertDialog.Builder(this)
                    .setTitle("Move note to Trash?")
                    .setNegativeButton("CANCEL", null)
                    .setPositiveButton("TRASH", (d, w) -> {
                        try {
                            if (autosave != null) handler.removeCallbacks(autosave);
                            vault.batch("trash", java.util.Collections.singletonList("note:" + id));
                            editingId = null; showScreen("notes");
                        } catch (Exception e) { error(e); }
                    }).show(), false));
            add(page, buttons, 55);
            info(page, "Created: " + note.getString("created_at") + "  •  Updated: " + note.getString("updated_at"));
            noteTitle = input("Note title", note.getString("title"), false);
            add(page, noteTitle, 52); addSpace(page, 9);
            noteBody = input("Write your note...", note.getString("body"), true);
            page.addView(noteBody, new LinearLayout.LayoutParams(-1, 0, 1));
            TextView autosaveInfo = text("AUTOSAVE: 1.2 SECONDS AFTER EDITING", 11, SUBTLE, false);
            add(page, autosaveInfo, 25);
            SimpleWatcher watcher = new SimpleWatcher() {
                @Override public void afterTextChanged(Editable s) {
                    if (autosave != null) handler.removeCallbacks(autosave);
                    autosave = () -> saveEditor(false);
                    handler.postDelayed(autosave, 1200);
                }
            };
            noteTitle.addTextChangedListener(watcher); noteBody.addTextChangedListener(watcher);
            vault.log("note_opened", "note", id, note.getString("title"));
        } catch (Exception ex) { error(ex); showScreen("notes"); }
    }

    private void saveEditor(boolean notify) {
        if (vault == null || editingId == null || noteTitle == null || noteBody == null) return;
        if (autosave != null) handler.removeCallbacks(autosave);
        try {
            boolean changed = vault.updateNote(editingId, noteTitle.getText().toString(), noteBody.getText().toString());
            if (notify) message("Note saved", changed ? "Encrypted changes saved locally." : "No changes to save.");
        } catch (Exception ex) { error(ex); }
    }

    private void fileDetails(VaultEngine.Item file) {
        String lower = file.name.toLowerCase(Locale.ROOT);
        boolean image = lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")
                || lower.endsWith(".webp") || lower.endsWith(".gif") || lower.endsWith(".bmp");
        List<String> actions = new ArrayList<>();
        actions.add("Export decrypted copy");
        if (image) actions.add("Preview image");
        actions.add("Select this file");
        new AlertDialog.Builder(this).setTitle(file.name).setItems(actions.toArray(new String[0]), (d, index) -> {
            if (index == 0) exportFile(file.id);
            else if (image && index == 1) previewImage(file.id);
            else { selected.add(file.key()); updateSelection(); }
        }).show();
    }

    private void previewImage(String id) {
        final byte[][] result = new byte[1][];
        async("Authenticating image", () -> result[0] = vault.preview(id, 8 * 1024 * 1024), () -> {
            showScreen("files");
            byte[] bytes = result[0];
            BitmapFactory.Options bounds = new BitmapFactory.Options();
            bounds.inJustDecodeBounds = true;
            BitmapFactory.decodeByteArray(bytes, 0, bytes.length, bounds);
            int sample = 1;
            while (bounds.outWidth / sample > 2048 || bounds.outHeight / sample > 2048) sample *= 2;
            BitmapFactory.Options options = new BitmapFactory.Options(); options.inSampleSize = sample;
            Bitmap bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length, options);
            if (bitmap == null) { message("Preview unavailable", "This file is not a supported image."); return; }
            ImageView image = new ImageView(this); image.setImageBitmap(bitmap);
            image.setAdjustViewBounds(true); image.setPadding(dp(8), dp(8), dp(8), dp(8));
            new AlertDialog.Builder(this).setView(image).setPositiveButton("CLOSE", null).show();
        });
    }

    private void logsScreen() throws Exception {
        heading("LOGS");
        info(page, "Encrypted activity history  •  latest first");
        EditText search = input("Search activity...", "", false);
        add(page, search, 48); addSpace(page, 9);
        ListView list = new ListView(this);
        addList(list);
        Runnable render = () -> {
            try {
                List<JSONObject> entries = vault.logs(search.getText().toString());
                BaseAdapter adapter = new BaseAdapter() {
                    @Override public int getCount() { return entries.size(); }
                    @Override public Object getItem(int position) { return entries.get(position); }
                    @Override public long getItemId(int position) { return position; }
                    @Override public View getView(int position, View old, ViewGroup parent) {
                        JSONObject item = entries.get(position);
                        LinearLayout box = vertical();
                        box.setPadding(dp(11), dp(11), dp(11), dp(11));
                        box.setBackground(panel(CARD, BORDER, 4));
                        box.addView(text(item.optString("action", "unknown").toUpperCase(Locale.ROOT), 13, RED, true));
                        box.addView(text(item.optString("at", ""), 11, SUBTLE, false));
                        box.addView(text(item.optString("detail", ""), 12, WHITE, false));
                        return box;
                    }
                };
                list.setAdapter(adapter);
            } catch (Exception ex) { error(ex); }
        };
        render.run();
        search.addTextChangedListener(new SimpleWatcher() {
            @Override public void afterTextChanged(Editable s) { render.run(); }
        });
    }

    private void settingsScreen() throws Exception {
        heading("SETTINGS");
        LinearLayout col = scrollColumn(page);
        info(col, vault.stats());
        addSpace(col, 8);
        section(col, "ENCRYPTED BACKUPS");
        info(col, "Portable and still AES-256 encrypted. Compatible with the Fedora vault v1 archive layout.");
        marginButton(col, button("EXPORT ENCRYPTED ZIP", () -> createBackup("zip"), true));
        marginButton(col, button("EXPORT ENCRYPTED TAR.GZ", () -> createBackup("tar.gz"), false));
        marginButton(col, button("EXPORT ENCRYPTED TAR", () -> createBackup("tar"), false));
        marginButton(col, button("RESTORE ENCRYPTED BACKUP", this::chooseBackup, false));
        if (new File(getFilesDir(), "vault-previous").exists()) {
            marginButton(col, button("SWITCH TO PREVIOUS LOCAL VAULT", this::confirmSwitchPrevious, false));
            marginButton(col, button("DISCARD PREVIOUS VAULT", this::confirmDiscardPrevious, false));
        }
        addSpace(col, 17);
        section(col, "DECRYPTED EXPORT");
        info(col, "WARNING: Plain ZIP contains readable notes, files and logs. It must be protected separately.");
        marginButton(col, button("EXPORT READABLE ZIP", () -> new AlertDialog.Builder(this)
                .setTitle("EXPORT UNENCRYPTED DATA?")
                .setMessage("This ZIP will NOT be password protected. Anyone who receives it can read your data.")
                .setNegativeButton("CANCEL", null)
                .setPositiveButton("I UNDERSTAND", (d, w) -> saveDocument(SAVE_READABLE, "application/zip", "vault-readable.zip"))
                .show(), false));
        addSpace(col, 17);
        section(col, "INTEGRITY / SECURITY");
        marginButton(col, button("VERIFY ALL ENCRYPTED FILES", () -> async("Checking AES-GCM tags", () -> {
            VaultEngine.Verification v = vault.verifyAll();
            runOnUiThread(() -> message("Integrity check", v.checked + " files checked.\n"
                    + (v.errors.isEmpty() ? "No errors found." : String.join("\n", v.errors))));
        }, () -> showScreen("settings")), false));
        marginButton(col, button("LOCK VAULT", this::lockVault, true));
        addSpace(col, 15);
        info(col, "Storage: private Android app data. Import copies encrypted bytes into the vault; it never links to Downloads.");
        info(col, "No network permissions. No cloud backup. Auto-lock after 15 minutes idle. Screenshots blocked for privacy.");
        info(col, "Lost passwords cannot be recovered. Permanent deletion cannot guarantee erasure from flash wear-leveling or old backups.");
    }
    private void section(LinearLayout into, String title) {
        TextView t = text(title, 15, RED, true); add(into, t, 35);
    }

    private void lockVault() {
        if (busy) return;
        if (autosave != null) handler.removeCallbacks(autosave);
        if (vault != null) {
            if ("editor".equals(screen)) saveEditor(false);
            try { vault.lock(); } catch (Exception e) { error(e); }
            vault = null;
        }
        showLogin();
    }

    private void pickFiles() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE); i.setType("*/*");
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        startActivityForResult(i, PICK_FILES);
    }
    private void pickFolder() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        startActivityForResult(i, PICK_TREE);
    }
    private void exportFile(String id) {
        exportId = id;
        try {
            JSONObject meta = vault.file(id);
            saveDocument(SAVE_FILE, "application/octet-stream", meta.getString("name"));
        } catch (Exception e) { error(e); }
    }
    private void createBackup(String format) {
        backupFormat = format;
        String mime = format.equals("zip") ? "application/zip" : format.equals("tar")
                ? "application/x-tar" : "application/gzip";
        saveDocument(SAVE_BACKUP, mime, "kayralrics-vault-backup." + format);
    }
    private void chooseBackup() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, PICK_BACKUP);
    }
    private void saveDocument(int request, String mime, String name) {
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE); i.setType(mime);
        i.putExtra(Intent.EXTRA_TITLE, name);
        startActivityForResult(i, request);
    }
    private String displayName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) return cursor.getString(0);
        } catch (Exception ignored) { }
        String path = uri.getLastPathSegment();
        return path == null ? "imported-file" : path.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result != RESULT_OK || data == null
                || (data.getData() == null && !(request == PICK_FILES && data.getClipData() != null))) return;
        if (timedOut() && vault != null) { lockVault(); message("Session expired", "Unlock the vault and choose the file again."); return; }
        Uri uri = data.getData();
        if (request == PICK_FILES) {
            List<Uri> list = new ArrayList<>();
            ClipData clips = data.getClipData();
            if (clips != null) {
                for (int x = 0; x < clips.getItemCount(); x++) list.add(clips.getItemAt(x).getUri());
            } else if (uri != null) list.add(uri);
            if (list.isEmpty()) return;
            async("Encrypting imported files", () -> {
                for (Uri file : list) {
                    String name = displayName(file);
                    try (InputStream in = getContentResolver().openInputStream(file)) {
                        if (in == null) throw new java.io.IOException("Cannot open selected file");
                        vault.importFile(in, name, safeName(name));
                    }
                }
            }, () -> { showScreen("files"); message("Import complete", list.size() + " file(s) copied into encrypted app storage."); });
        } else if (request == PICK_TREE) {
            async("Encrypting selected folder", () -> {
                String doc = DocumentsContract.getTreeDocumentId(uri);
                String name = queryTreeName(uri, doc);
                int[] count = new int[]{0};
                walkTree(uri, doc, safeName(name), 0, count);
                vault.log("folder_imported", "folder", "", count[0] + " files");
            }, () -> { showScreen("files"); message("Folder import complete", "Folder contents copied into private encrypted storage."); });
        } else if (request == SAVE_FILE) {
            String id = exportId;
            async("Decrypting selected file", () -> {
                try (OutputStream out = getContentResolver().openOutputStream(uri, "w")) {
                    if (out == null) throw new java.io.IOException("Cannot write destination");
                    vault.exportFile(id, out);
                }
            }, () -> { showScreen("files"); message("Export finished", "A readable copy was saved to the location you chose."); });
        } else if (request == SAVE_BACKUP) {
            String format = backupFormat;
            async("Exporting encrypted " + format + " archive", () -> {
                try (OutputStream out = getContentResolver().openOutputStream(uri, "w")) {
                    if (out == null) throw new java.io.IOException("Cannot write backup destination");
                    vault.encryptedBackup(out, format);
                }
            }, () -> { showScreen("settings"); message("Encrypted backup saved", "Your backup contains ciphertext only and needs the vault password."); });
        } else if (request == SAVE_READABLE) {
            async("Exporting readable ZIP", () -> {
                try (OutputStream out = getContentResolver().openOutputStream(uri, "w")) {
                    if (out == null) throw new java.io.IOException("Cannot write ZIP destination");
                    vault.readableZip(out);
                }
            }, () -> { showScreen("settings"); message("Readable ZIP exported", "Keep this unencrypted archive private."); });
        } else if (request == PICK_BACKUP) {
            restorePasswordDialog(uri);
        }
    }

    private String safeName(String input) {
        String value = (input == null ? "unnamed" : input).replace('/', '_').replace('\\', '_').replace('\u0000', '_')
                .replace(':', '_').trim();
        if (value.equals(".") || value.equals("..") || value.isEmpty()) return "unnamed";
        return value;
    }
    private String queryTreeName(Uri tree, String docId) {
        Uri document = DocumentsContract.buildDocumentUriUsingTree(tree, docId);
        try (Cursor c = getContentResolver().query(document,
                new String[]{DocumentsContract.Document.COLUMN_DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) return c.getString(0);
        }
        return "folder";
    }
    private void walkTree(Uri tree, String folderId, String prefix, int depth, int[] count) throws Exception {
        if (depth > 32 || count[0] > 100000) throw new java.io.IOException("Folder is too deep or contains too many items");
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, folderId);
        try (Cursor c = getContentResolver().query(children, new String[]{
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE}, null, null, null)) {
            if (c == null) throw new java.io.IOException("Folder provider did not return files");
            while (c.moveToNext()) {
                String id = c.getString(0), name = safeName(c.getString(1)), mime = c.getString(2);
                String rel = prefix + "/" + name;
                if (DocumentsContract.Document.MIME_TYPE_DIR.equals(mime)) {
                    walkTree(tree, id, rel, depth + 1, count);
                } else {
                    Uri document = DocumentsContract.buildDocumentUriUsingTree(tree, id);
                    try (InputStream in = getContentResolver().openInputStream(document)) {
                        if (in == null) throw new java.io.IOException("Cannot open " + name);
                        vault.importFile(in, name, rel);
                    }
                    count[0]++;
                }
            }
        }
    }

    private void restorePasswordDialog(Uri archive) {
        String archiveName = displayName(archive);
        EditText password = passwordInput("Password of this encrypted backup");
        new AlertDialog.Builder(this).setTitle("RESTORE ENCRYPTED VAULT")
                .setMessage("A valid backup replaces the active vault. The previous encrypted vault is retained locally for rollback. Use the backup's own password.")
                .setView(password).setNegativeButton("CANCEL", null)
                .setPositiveButton("RESTORE", (d, which) -> {
                    char[] secret = password.getText().toString().toCharArray();
                    if (secret.length == 0) { message("Password missing", "A backup password is required."); return; }
                    async("Restoring & validating ciphertext", () -> {
                        if (vault != null) { vault.lock(); vault = null; }
                        try (InputStream in = getContentResolver().openInputStream(archive)) {
                            if (in == null) throw new java.io.IOException("Cannot open backup");
                            VaultEngine.restoreBackup(vaultFolder, in, archiveName, secret);
                            vault = VaultEngine.open(vaultFolder, secret);
                        } finally { Arrays.fill(secret, '\0'); }
                    }, () -> { showScreen("notes"); message("Backup restored", "Encrypted vault restored and authenticated successfully."); });
                }).show();
    }
    private void confirmSwitchPrevious() {
        new AlertDialog.Builder(this).setTitle("SWITCH VAULTS")
                .setMessage("Exchange the current vault with your preserved previous encrypted vault? You will need the other vault's password.")
                .setNegativeButton("CANCEL", null)
                .setPositiveButton("SWITCH", (d, which) -> async("Switching local vaults", () -> {
                    if (vault != null) { vault.lock(); vault = null; }
                    VaultEngine.swapPrevious(vaultFolder);
                }, () -> { showLogin(); message("Vault switched", "Unlock the recovered vault with its password."); })).show();
    }

    private void confirmDiscardPrevious() {
        File previous = new File(getFilesDir(), "vault-previous");
        if (!previous.isDirectory()) { message("No previous vault", "There is no preserved vault to discard."); return; }
        EditText confirmation = input("Type DELETE to confirm", "", false);
        new AlertDialog.Builder(this).setTitle("PERMANENTLY DISCARD PREVIOUS VAULT")
                .setMessage("This deletes the saved rollback vault. Only continue after making an independent encrypted backup.")
                .setView(confirmation)
                .setNegativeButton("CANCEL", null)
                .setPositiveButton("DELETE", (d, which) -> {
                    if (!"DELETE".equals(confirmation.getText().toString())) {
                        message("Not deleted", "Enter DELETE in capital letters to confirm."); return;
                    }
                    async("Removing preserved encrypted vault", () -> VaultEngine.deleteTree(previous), () -> {
                        if (vault == null) showLogin(); else showScreen("settings");
                        message("Previous vault discarded", "The preserved local rollback vault has been removed.");
                    });
                }).show();
    }

    @Override public void onBackPressed() {
        if (busy) return;
        if ("editor".equals(screen)) { saveEditor(false); showScreen("notes"); }
        else if (vault != null && !"notes".equals(screen)) showScreen("notes");
        else if (vault != null) lockVault();
        else super.onBackPressed();
    }

    private abstract static class SimpleWatcher implements TextWatcher {
        @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
        @Override public void onTextChanged(CharSequence s, int start, int before, int count) { }
    }
}
