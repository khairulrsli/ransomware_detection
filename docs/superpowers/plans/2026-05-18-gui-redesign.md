# GUI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the light tkinter theme in `app/main.py` with the Dark/Cyber design (GitHub-dark palette, Verdict+IOCs Split result card, Visual Dashboard metrics panel).

**Architecture:** Single-file change — `app/main.py` only. All detection logic, threading, and callbacks stay identical. Six logical groups: color palette → ttk styles → header/footer → Analysis tab layout → result card swap → metrics panel widgets. No new files, no new dependencies.

**Tech Stack:** Python 3, tkinter (tk + ttk), no new packages.

> **Note on TDD:** tkinter widget construction has no unit-testable surface. Each task ends with a visual smoke-test: launch the app and confirm the changed area looks correct before committing.

---

### Task 1: Replace color palette constants

**Files:**
- Modify: `app/main.py:787-809` (theme palette block)

- [ ] **Step 1: Replace the palette block**

Find and replace the entire `# ── THEME PALETTE (Light)` block (lines 786–809) with:

```python
# ── THEME PALETTE (Dark / Cyber) ──────────────────────────────────────────────
BG_DEEP         = "#0d1117"   # window background
BG_CARD         = "#161b22"   # card / panel backgrounds
BG_INPUT        = "#21262d"   # input fields, progress track
BORDER_COLOR    = "#30363d"   # all card/panel borders
TEXT_PRIMARY    = "#e6edf3"   # primary text
TEXT_MUTED      = "#8b949e"   # labels, secondary text
ACCENT_BLUE     = "#58a6ff"   # accent, links
DANGER_RED      = "#ff4444"   # ransomware verdict, critical IOCs
WARN_ORANGE     = "#ffa500"   # warning IOCs
SUCCESS_GREEN   = "#3fb950"   # benign verdict, quarantine confirmed
BTN_BLUE        = "#1f6feb"   # primary action button fill
BTN_BLUE_BORDER = "#388bfd"
DANGER_DARK     = "#1a0000"   # ransomware card background
SUCCESS_DARK    = "#0f3d1f"   # benign card background

# Aliases kept so existing references compile unchanged
BG_DARK         = BG_DEEP
SURFACE         = BG_CARD
SURFACE_LIGHT   = BG_INPUT
PRIMARY_COLOR   = ACCENT_BLUE
SECONDARY_COLOR = ACCENT_BLUE
SUCCESS_COLOR   = SUCCESS_GREEN
DANGER_COLOR    = DANGER_RED
WARNING_COLOR   = WARN_ORANGE
BG_COLOR        = BG_DEEP
DARK_TEXT       = TEXT_PRIMARY
LIGHT_TEXT      = TEXT_MUTED
INPUT_BG        = BG_INPUT
HEADER_BG       = BG_CARD
```

- [ ] **Step 2: Update root config**

Change:
```python
root.config(bg=BG_DARK)
```
to:
```python
root.config(bg=BG_DEEP)
```

- [ ] **Step 3: Smoke test — launch app**

```
cd C:\Users\vboxuser\Desktop\ransomware_detection\app
python main.py
```
Expected: window opens, background is `#0d1117` near-black. Tabs and cards will still be light — that's fine, palette is wired but styling not yet applied.

- [ ] **Step 4: Commit**

```
git add app/main.py
git commit -m "refactor: replace light palette with dark/cyber color constants"
```

---

### Task 2: Update ttk styles + window background

**Files:**
- Modify: `app/main.py` — ttk style block (~lines 840–850) and `at`/`sc`/`qt_tab` frame bg

- [ ] **Step 1: Replace ttk style block**

Find the `# ── TTK STYLES` block and replace with:

```python
# ── TTK STYLES ─────────────────────────────────────────────────────────────────
style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook", background=BG_DEEP, borderwidth=0)
style.configure("TNotebook.Tab", background=BG_CARD, foreground=TEXT_MUTED,
                padding=[18, 10], font=BTN_FONT, borderwidth=0)
style.map("TNotebook.Tab",
          background=[("selected", BG_DEEP)],
          foreground=[("selected", ACCENT_BLUE)])
style.configure("Custom.Horizontal.TProgressbar",
                background=ACCENT_BLUE, troughcolor=BG_INPUT,
                borderwidth=0, thickness=8)
```

- [ ] **Step 2: Set notebook + tab frame backgrounds to dark**

Find and update the three tab frame definitions:
```python
at = tk.Frame(notebook, bg=BG_DEEP)
```
```python
st_tab = tk.Frame(notebook, bg=BG_DEEP)
```
```python
qt_tab = tk.Frame(notebook, bg=BG_DEEP)
```

Also update inner container frames:
```python
ac = tk.Frame(at, bg=BG_DEEP)
sc = tk.Frame(st_tab, bg=BG_DEEP)
qc = tk.Frame(qt_tab, bg=BG_DEEP)
```

- [ ] **Step 3: Smoke test**

```
python main.py
```
Expected: tabs and window background are dark. Tab text: muted gray, active tab text: blue.

- [ ] **Step 4: Commit**

```
git add app/main.py
git commit -m "refactor: apply dark ttk notebook styles and tab frame backgrounds"
```

---

### Task 3: Restyle header and footer

**Files:**
- Modify: `app/main.py` — header block (~lines 852–878) and footer block (~lines 1024–1036)

- [ ] **Step 1: Replace header block**

Find `# ── HEADER ──` block and replace everything from `header = tk.Frame(...)` through the end of the header section with:

```python
# ── HEADER ─────────────────────────────────────────────────────────────────────
header = tk.Frame(root, bg=BG_CARD, height=52)
header.pack(fill="x")
header.pack_propagate(False)
tk.Frame(root, bg=BORDER_COLOR, height=1).pack(fill="x")

hf = tk.Frame(header, bg=BG_CARD)
hf.pack(fill="both", expand=True, padx=20)

title_f = tk.Frame(hf, bg=BG_CARD)
title_f.pack(side="left", fill="y", pady=8)
tk.Label(title_f, text="●", font=("Segoe UI", 10), fg=DANGER_RED,
         bg=BG_CARD).pack(side="left", padx=(0, 8))
tk.Label(title_f, text="RANSOMWARE DETECTION SYSTEM",
         font=("Segoe UI", 11, "bold"), fg=ACCENT_BLUE, bg=BG_CARD).pack(side="left")

si = tk.Frame(hf, bg=BG_CARD)
si.pack(side="right", pady=8)
active_bg = tk.Frame(si, bg="#0f3d1f", padx=8, pady=2)
active_bg.pack(side="right")
tk.Label(active_bg, text="● ACTIVE", font=("Segoe UI", 9, "bold"),
         fg=SUCCESS_GREEN, bg="#0f3d1f").pack()
```

- [ ] **Step 2: Replace footer block**

Find `# ── FOOTER: SESSION HISTORY ──` and replace from `footer = tk.Frame(...)` to end with:

```python
# ── FOOTER: SESSION HISTORY ───────────────────────────────────────────────────
tk.Frame(root, bg=BORDER_COLOR, height=1).pack(fill="x", side="bottom")
footer = tk.Frame(root, bg=BG_CARD)
footer.pack(fill="x", side="bottom")
fh = tk.Frame(footer, bg=BG_CARD)
fh.pack(fill="x", padx=20, pady=(8, 0))
tk.Label(fh, text="SCAN HISTORY", font=("Segoe UI", 8, "bold"),
         fg=TEXT_MUTED, bg=BG_CARD, letter_spacing=1).pack(side="left")
history_count_var = tk.StringVar(value="0 scans this session")
tk.Label(fh, textvariable=history_count_var, font=("Segoe UI", 8),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="right")
history_text = tk.Text(footer, font=MONO_FONT, height=2, width=110,
                       state="disabled", wrap="none", bg=BG_CARD, fg=TEXT_PRIMARY,
                       relief="flat", padx=10, pady=6,
                       highlightbackground=BORDER_COLOR, highlightthickness=0)
history_text.pack(fill="x", expand=False, padx=20, pady=(4, 10))
history_text.tag_configure("ransom", foreground=DANGER_RED)
history_text.tag_configure("benign", foreground=SUCCESS_GREEN)
```

- [ ] **Step 3: Update `add_history_entry` to use color tags and update count**

Replace the `add_history_entry` function body:

```python
def add_history_entry(filename, verdict, confidence):
    ts = datetime.now().strftime("%H:%M:%S")
    tag = "ransom" if "RANSOM" in verdict.upper() else "benign"
    dot = "●"
    entry = f"  {dot} {filename[:28]}  [{verdict}]  {confidence}"
    analysis_history.insert(0, (entry, tag))
    if len(analysis_history) > 8:
        analysis_history.pop()
    history_text.config(state="normal")
    history_text.delete("1.0", "end")
    for item, t in analysis_history:
        history_text.insert("end", item + "   ", t)
    history_text.config(state="disabled")
    history_count_var.set(f"{len(analysis_history)} scans this session")
```

Also update `analysis_history` initial value (keep as `[]`) and update `clear_history` to reset `history_count_var`:

In `clear_history`, after `analysis_history.clear()` add:
```python
    history_count_var.set("0 scans this session")
```

- [ ] **Step 4: Smoke test**

```
python main.py
```
Expected: dark header with red dot + blue app name + green ACTIVE badge. Dark footer with SCAN HISTORY label.

- [ ] **Step 5: Commit**

```
git add app/main.py
git commit -m "refactor: restyle header and footer to dark/cyber theme"
```

---

### Task 4: Rebuild Analysis tab layout (file row + progress bar)

**Files:**
- Modify: `app/main.py` — Analysis tab section (~lines 883–965)

- [ ] **Step 1: Replace the Analysis tab content**

Find `# ── TAB 1: ANALYSIS ──` and replace everything from `at = tk.Frame(notebook...)` through the end of the right panel metrics section with:

```python
# ── TAB 1: ANALYSIS ───────────────────────────────────────────────────────────
at = tk.Frame(notebook, bg=BG_DEEP)
notebook.add(at, text="  Analysis  ")
ac = tk.Frame(at, bg=BG_DEEP)
ac.pack(fill="both", expand=True, padx=12, pady=10)

# ── File row ──────────────────────────────────────────────────────────────────
file_row = tk.Frame(ac, bg=BG_DEEP)
file_row.pack(fill="x", pady=(0, 8))

file_path_var = tk.StringVar(value="No file selected")
path_entry = tk.Entry(file_row, textvariable=file_path_var, font=MONO_FONT,
                      bg=BG_CARD, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                      relief="flat", bd=0, highlightbackground=BORDER_COLOR,
                      highlightthickness=1, readonlybackground=BG_CARD,
                      state="readonly")
path_entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 6))

browse_btn = tk.Button(file_row, text="Browse", font=BTN_FONT,
                       bg=BG_INPUT, fg=TEXT_PRIMARY, padx=14, pady=7,
                       border=0, cursor="hand2",
                       activebackground=BORDER_COLOR, activeforeground=TEXT_PRIMARY,
                       highlightbackground=BORDER_COLOR, highlightthickness=1,
                       command=start_analysis)
browse_btn.pack(side="left", padx=(0, 6))

scan_btn = tk.Button(file_row, text="Scan", font=("Segoe UI", 10, "bold"),
                     bg=BTN_BLUE, fg="white", padx=20, pady=7,
                     border=0, cursor="hand2",
                     activebackground=BTN_BLUE_BORDER, activeforeground="white",
                     command=start_analysis)
scan_btn.pack(side="left")

# ── Progress bar card ─────────────────────────────────────────────────────────
prog_card = tk.Frame(ac, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                     highlightthickness=1)
prog_card.pack(fill="x", pady=(0, 8))

prog_inner = tk.Frame(prog_card, bg=BG_CARD)
prog_inner.pack(fill="x", padx=14, pady=8)

prog_label_row = tk.Frame(prog_inner, bg=BG_CARD)
prog_label_row.pack(fill="x", pady=(0, 4))
tk.Label(prog_label_row, text="Behavioral Analysis", font=("Segoe UI", 9),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
prog_info_var = tk.StringVar(value="")
tk.Label(prog_label_row, textvariable=prog_info_var, font=("Segoe UI", 9),
         fg=ACCENT_BLUE, bg=BG_CARD).pack(side="right")

prog_track = tk.Frame(prog_inner, bg=BG_INPUT, height=5)
prog_track.pack(fill="x")
prog_track.pack_propagate(False)
prog_fill = tk.Frame(prog_track, bg=ACCENT_BLUE, height=5)
prog_fill.place(x=0, y=0, relheight=1.0, relwidth=0.0)

status_label = tk.Label(prog_inner, textvariable=status_var, font=("Segoe UI", 9),
                        fg=TEXT_MUTED, bg=BG_CARD, anchor="w")
status_label.pack(fill="x", pady=(3, 0))

# ── Result row: verdict card (left) + metrics panel (right) ───────────────────
result_row = tk.Frame(ac, bg=BG_DEEP)
result_row.pack(fill="both", expand=True)

# Verdict card ─────────────────────────────────────────────────────────────────
verdict_outer = tk.Frame(result_row, bg=BG_DEEP, width=170)
verdict_outer.pack(side="left", fill="y", padx=(0, 8))
verdict_outer.pack_propagate(False)

# Idle placeholder (shown before first scan)
verdict_idle = tk.Frame(verdict_outer, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                        highlightthickness=1)
verdict_idle.pack(fill="both", expand=True)
tk.Label(verdict_idle, text="No scan\nyet", font=("Segoe UI", 10),
         fg=TEXT_MUTED, bg=BG_CARD, justify="center").pack(expand=True)

# Ransomware card (hidden until ransomware detected)
verdict_ransom = tk.Frame(verdict_outer, bg=DANGER_DARK,
                          highlightbackground=DANGER_RED, highlightthickness=1)
vr = tk.Frame(verdict_ransom, bg=DANGER_DARK)
vr.pack(fill="both", expand=True, padx=10, pady=10)
tk.Label(vr, text="⚠", font=("Segoe UI", 20), fg=DANGER_RED,
         bg=DANGER_DARK).pack(pady=(0, 2))
tk.Label(vr, text="RANSOMWARE", font=("Segoe UI", 9, "bold"),
         fg=DANGER_RED, bg=DANGER_DARK, letter_spacing=2).pack()
tk.Label(vr, text="DETECTED", font=("Segoe UI", 8),
         fg="#ff666688", bg=DANGER_DARK).pack(pady=(0, 8))
vr_score_frame = tk.Frame(vr, bg="#2a0000")
vr_score_frame.pack(fill="x", pady=(0, 4))
tk.Label(vr_score_frame, text="THREAT SCORE", font=("Segoe UI", 7),
         fg=TEXT_MUTED, bg="#2a0000").pack(pady=(4, 0))
verdict_score_var = tk.StringVar(value="0.000")
tk.Label(vr_score_frame, textvariable=verdict_score_var,
         font=("Segoe UI", 16, "bold"), fg=DANGER_RED, bg="#2a0000").pack(pady=(0, 4))
vr_cvss_frame = tk.Frame(vr, bg="#2a0000")
vr_cvss_frame.pack(fill="x", pady=(0, 8))
verdict_cvss_var = tk.StringVar(value="CVSS –")
tk.Label(vr_cvss_frame, textvariable=verdict_cvss_var,
         font=("Segoe UI", 9, "bold"), fg=WARN_ORANGE, bg="#2a0000").pack(pady=2)
verdict_severity_var = tk.StringVar(value="")
tk.Label(vr_cvss_frame, textvariable=verdict_severity_var,
         font=("Segoe UI", 8), fg=DANGER_RED, bg="#2a0000").pack(pady=(0, 4))
quarantine_btn = tk.Button(vr, text="QUARANTINE", font=("Segoe UI", 8, "bold"),
                           bg=BG_CARD, fg=ACCENT_BLUE, padx=6, pady=4,
                           border=0, cursor="hand2",
                           activebackground=BG_INPUT, activeforeground=ACCENT_BLUE)
quarantine_btn.pack(fill="x", pady=(0, 3))
delete_btn = tk.Button(vr, text="DELETE", font=("Segoe UI", 8, "bold"),
                       bg=DANGER_DARK, fg=DANGER_RED, padx=6, pady=4,
                       border=0, cursor="hand2", state="disabled",
                       highlightbackground=DANGER_RED, highlightthickness=1,
                       activebackground="#2a0000", activeforeground=DANGER_RED)
delete_btn.pack(fill="x")

# Benign card (hidden until benign result)
verdict_benign = tk.Frame(verdict_outer, bg=SUCCESS_DARK,
                          highlightbackground=SUCCESS_GREEN, highlightthickness=1)
vb = tk.Frame(verdict_benign, bg=SUCCESS_DARK)
vb.pack(fill="both", expand=True, padx=10, pady=10)
tk.Label(vb, text="✓", font=("Segoe UI", 20), fg=SUCCESS_GREEN,
         bg=SUCCESS_DARK).pack(pady=(0, 2))
tk.Label(vb, text="SAFE", font=("Segoe UI", 9, "bold"),
         fg=SUCCESS_GREEN, bg=SUCCESS_DARK).pack()
tk.Label(vb, text="BENIGN", font=("Segoe UI", 8),
         fg="#3fb95088", bg=SUCCESS_DARK).pack(pady=(0, 8))
vb_score_frame = tk.Frame(vb, bg="#0a2a12")
vb_score_frame.pack(fill="x", pady=(0, 4))
tk.Label(vb_score_frame, text="THREAT SCORE", font=("Segoe UI", 7),
         fg=TEXT_MUTED, bg="#0a2a12").pack(pady=(4, 0))
benign_score_var = tk.StringVar(value="0.000")
tk.Label(vb_score_frame, textvariable=benign_score_var,
         font=("Segoe UI", 16, "bold"), fg=SUCCESS_GREEN, bg="#0a2a12").pack(pady=(0, 4))
benign_cvss_var = tk.StringVar(value="CVSS –")
vb_cvss_frame = tk.Frame(vb, bg="#0a2a12")
vb_cvss_frame.pack(fill="x")
tk.Label(vb_cvss_frame, textvariable=benign_cvss_var,
         font=("Segoe UI", 9, "bold"), fg=SUCCESS_GREEN, bg="#0a2a12").pack(pady=4)

# Metrics panel ────────────────────────────────────────────────────────────────
metrics_outer = tk.Frame(result_row, bg=BG_CARD,
                         highlightbackground=BORDER_COLOR, highlightthickness=1)
metrics_outer.pack(side="left", fill="both", expand=True)
mp = tk.Frame(metrics_outer, bg=BG_CARD)
mp.pack(fill="both", expand=True, padx=14, pady=10)

# ML confidence header row
ml_hdr = tk.Frame(mp, bg=BG_CARD)
ml_hdr.pack(fill="x", pady=(0, 8))
tk.Label(ml_hdr, text="ML Confidence", font=("Segoe UI", 9),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
ml_conf_var = tk.StringVar(value="—")
tk.Label(ml_hdr, textvariable=ml_conf_var,
         font=("Segoe UI", 13, "bold"), fg=DANGER_RED, bg=BG_CARD).pack(side="right")

# Progress bars — (label, value_var, fill_frame, max_val, color)
BAR_DEFS = [
    ("ML Score",    0.0, DANGER_RED,    1.0),
    ("Write Ops",   0,   WARN_ORANGE,   200.0),
    ("Rapid Writes",0,   WARN_ORANGE,   10.0),
    ("Busy Loops",  0,   ACCENT_BLUE,   20.0),
    ("Network Conn",0,   ACCENT_BLUE,   10.0),
]
bar_value_vars = []
bar_fills = []
for label_text, _, bar_color, _ in BAR_DEFS:
    brow = tk.Frame(mp, bg=BG_CARD)
    brow.pack(fill="x", pady=2)
    bl = tk.Frame(brow, bg=BG_CARD)
    bl.pack(fill="x", pady=(0, 2))
    tk.Label(bl, text=label_text, font=("Segoe UI", 8),
             fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
    val_var = tk.StringVar(value="—")
    bar_value_vars.append(val_var)
    tk.Label(bl, textvariable=val_var, font=("Segoe UI", 8),
             fg=bar_color, bg=BG_CARD).pack(side="right")
    track = tk.Frame(brow, bg=BG_INPUT, height=4)
    track.pack(fill="x")
    track.pack_propagate(False)
    fill = tk.Frame(track, bg=bar_color, height=4)
    fill.place(x=0, y=0, relheight=1.0, relwidth=0.0)
    bar_fills.append(fill)

# Divider
tk.Frame(mp, bg=BORDER_COLOR, height=1).pack(fill="x", pady=8)

# IOC badges container
ioc_label_row = tk.Frame(mp, bg=BG_CARD)
ioc_label_row.pack(fill="x", pady=(0, 4))
tk.Label(ioc_label_row, text="IOC INDICATORS", font=("Segoe UI", 8, "bold"),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
ioc_badges_frame = tk.Frame(mp, bg=BG_CARD)
ioc_badges_frame.pack(fill="x")
tk.Label(ioc_badges_frame, text="No scan yet", font=("Segoe UI", 8),
         fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")

# Action status row (shown after ransomware result)
action_status_frame = tk.Frame(mp, bg="#0f1f0f",
                               highlightbackground="#238636", highlightthickness=1)
action_status_var = tk.StringVar(value="")

# Keep metrics_text as a dummy so existing set_text_widget calls don't crash
# (will be replaced in Task 5)
metrics_text = tk.Text(mp, height=1, width=1, state="disabled")
metrics_text.pack_forget()
```

- [ ] **Step 2: Update `set_progress` to drive the new progress fill**

Replace the `set_progress` function:

```python
def set_progress(status, progress, progress_text):
    status_var.set(status)
    progress_var.set(progress)
    progress_text_var.set(progress_text)
    prog_info_var.set(progress_text)
    # Animate fill bar (0–100 → 0.0–1.0 relwidth)
    frac = max(0.0, min(1.0, progress / 100.0))
    prog_fill.place(relwidth=frac)
```

- [ ] **Step 3: Smoke test**

```
python main.py
```
Expected: Analysis tab shows file row with Browse/Scan buttons, dark progress card, idle verdict card ("No scan yet"), metrics panel with empty bars.

- [ ] **Step 4: Commit**

```
git add app/main.py
git commit -m "refactor: rebuild Analysis tab layout with dark verdict card and metrics panel"
```

---

### Task 5: Wire verdict card + metrics panel to scan results

**Files:**
- Modify: `app/main.py` — `analyze_in_thread`, `_show_benign`, helper functions

- [ ] **Step 1: Add `_update_metrics_panel` helper**

Add this function just before `analyze_in_thread`:

```python
def _update_metrics_panel(ml_score, write_ops, rapid_writes, busy_loops,
                          network_ops, ioc_items, action_text=None):
    """
    ioc_items: list of (name, count, severity) where severity is
               'critical', 'warning', or 'info'.
    action_text: string like "Process killed · Files quarantined" or None.
    """
    # Update ML confidence header
    ml_conf_var.set(f"{ml_score*100:.1f}%")

    # Bar values and fill widths
    bar_data = [
        (ml_score,       1.0),
        (write_ops,      200.0),
        (rapid_writes,   10.0),
        (busy_loops,     20.0),
        (network_ops,    10.0),
    ]
    raw_display = [f"{ml_score:.3f}", str(write_ops), str(rapid_writes),
                   str(busy_loops), str(network_ops)]
    for i, ((val, max_val), display) in enumerate(zip(bar_data, raw_display)):
        bar_value_vars[i].set(display)
        frac = min(1.0, float(val) / max_val) if max_val > 0 else 0.0
        bar_fills[i].place(relwidth=frac)

    # IOC badges — clear and rebuild
    for w in ioc_badges_frame.winfo_children():
        w.destroy()
    if not ioc_items:
        tk.Label(ioc_badges_frame, text="No indicators triggered",
                 font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).pack(side="left")
    else:
        SEVERITY_STYLE = {
            "critical": ("#3d0000", DANGER_RED,   "#ff444455"),
            "warning":  ("#3d1a00", WARN_ORANGE,  "#ffa50055"),
            "info":     (BG_INPUT,  TEXT_MUTED,   BORDER_COLOR),
        }
        for (name, count, severity) in ioc_items:
            bg_c, fg_c, bd_c = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
            chip = tk.Frame(ioc_badges_frame, bg=bg_c,
                            highlightbackground=bd_c, highlightthickness=1)
            chip.pack(side="left", padx=(0, 4), pady=2)
            tk.Label(chip, text=f"{name} ×{count}",
                     font=("Segoe UI", 8), fg=fg_c, bg=bg_c,
                     padx=6, pady=2).pack()

    # Action status row
    for w in action_status_frame.winfo_children():
        w.destroy()
    if action_text:
        tk.Label(action_status_frame, text=f"✓  {action_text}",
                 font=("Segoe UI", 9, "bold"), fg=SUCCESS_GREEN,
                 bg="#0f1f0f", padx=8, pady=4).pack(side="left")
        action_status_frame.pack(fill="x", pady=(6, 0))
    else:
        action_status_frame.pack_forget()
```

- [ ] **Step 2: Add `_show_verdict_card` and `_hide_verdict_cards` helpers**

```python
def _hide_verdict_cards():
    verdict_idle.pack_forget()
    verdict_ransom.pack_forget()
    verdict_benign.pack_forget()

def _show_ransomware_card(composite, cvss_score, cvss_label):
    _hide_verdict_cards()
    verdict_score_var.set(f"{composite:.3f}")
    verdict_cvss_var.set(f"CVSS {cvss_score}")
    verdict_severity_var.set(cvss_label.upper())
    verdict_ransom.pack(fill="both", expand=True)

def _show_benign_card(composite, cvss_score, cvss_label):
    _hide_verdict_cards()
    benign_score_var.set(f"{composite:.3f}")
    benign_cvss_var.set(f"CVSS {cvss_score}")
    verdict_benign.pack(fill="both", expand=True)
```

- [ ] **Step 3: Update `_show_benign` function**

Replace the `_show_benign` function:

```python
def _show_benign(reason, history_verdict, history_conf):
    result_var.set("BENIGN FILE")
    confidence_var.set(f"Confidence: {history_conf}")
    status_var.set(f"Complete: {reason}")
    status_label.config(fg=SUCCESS_GREEN)
    progress_var.set(100)
    progress_text_var.set("100% - Complete")
    prog_info_var.set("100% — Complete")
    prog_fill.place(relwidth=1.0)
    add_history_entry(
        current_file.get().split("\n")[0],
        history_verdict, history_conf
    )
```

- [ ] **Step 4: Replace `set_text_widget` calls in `analyze_in_thread` for the ransomware branch**

In the `if is_ransomware:` block, find the `run_on_ui(set_text_widget, metrics_text, ...)` call and replace it with:

```python
            # Build IOC items list for badge display
            ioc_badge_items = []
            IOC_SEVERITY = {
                "CanaryViolation": "critical",
                "ShadowCopyDelete": "critical",
                "RapidFileWrite": "warning",
                "HighEntropyFile": "warning",
            }
            for name, count, unit in ioc_map:
                if count > 0:
                    sev = IOC_SEVERITY.get(name, "info")
                    ioc_badge_items.append((name, count, sev))

            action_str = (f"Process killed · "
                          f"{'Quarantined' if quarantined else 'Not quarantined'}")
            run_on_ui(_show_ransomware_card, composite, cvss_score, cvss_label, wait=True)
            run_on_ui(_update_metrics_panel,
                      prediction, write_ops, rapid_writes, busy_loops, network_ops,
                      ioc_badge_items, action_str, wait=True)
```

- [ ] **Step 5: Replace `set_text_widget` call in the benign branch**

In the `else:` (benign) branch, find the `run_on_ui(set_text_widget, metrics_text, ...)` call and replace it with:

```python
            ioc_badge_items = []
            for name, count, unit in ioc_map:
                if count > 0:
                    sev = IOC_SEVERITY.get(name, "info")
                    ioc_badge_items.append((name, count, sev))
            run_on_ui(_show_benign_card, composite, cvss_score, cvss_label, wait=True)
            run_on_ui(_update_metrics_panel,
                      prediction, write_ops, rapid_writes, busy_loops, network_ops,
                      ioc_badge_items, None, wait=True)
```

Also add `IOC_SEVERITY` dict before both branches (or define it once before the `if is_ransomware:` block):
```python
            IOC_SEVERITY = {
                "CanaryViolation": "critical",
                "ShadowCopyDelete": "critical",
                "RapidFileWrite": "warning",
                "HighEntropyFile": "warning",
            }
```

- [ ] **Step 6: Replace the "no activity" early-exit metrics call**

Find:
```python
            run_on_ui(set_text_widget, metrics_text,
                "No behavioral events recorded.\n" ...
```
Replace with:
```python
            run_on_ui(_show_benign_card, 0.0, 0.0, "None", wait=True)
            run_on_ui(_update_metrics_panel, 0.0, 0, 0, 0, 0, [], None, wait=True)
```

- [ ] **Step 7: Update `file_path_var` in `analyze_in_thread`**

At the top of `analyze_in_thread`, add after `file_name = ...`:
```python
        run_on_ui(file_path_var.set, file_path, wait=True)
        run_on_ui(current_file.set, f"{file_name}\n({file_size:.1f} KB)", wait=True)
```
(The existing `run_on_ui(current_file.set, ...)` line stays; add the `file_path_var` line above it.)

- [ ] **Step 8: Also hide verdict cards at scan start**

In `analyze_in_thread`, add after the `set_progress(...)` call at the top:
```python
        run_on_ui(_hide_verdict_cards, wait=True)
        run_on_ui(verdict_idle.pack, wait=True)
```

- [ ] **Step 9: Smoke test — full scan**

```
python main.py
```
Run a scan. Expected:
- Verdict card swaps to red ransomware card (or green benign card)
- Metrics panel shows filled progress bars and IOC badge chips
- Action status row shows green "✓ Process killed · Quarantined"

- [ ] **Step 10: Commit**

```
git add app/main.py
git commit -m "feat: wire verdict card and metrics dashboard to scan results"
```

---

### Task 6: Restyle Statistics and Quarantine tabs + Toplevel dialogs

**Files:**
- Modify: `app/main.py` — Statistics tab (~lines 967–999), Quarantine tab (~lines 1001–1021), `delete_quarantine_file` dialog

- [ ] **Step 1: Update Statistics tab widget colors**

Find the Statistics tab section and update all `bg=` and `fg=` values:

```python
# ── TAB 2: STATISTICS ─────────────────────────────────────────────────────────
st_tab = tk.Frame(notebook, bg=BG_DEEP)
notebook.add(st_tab, text="  Statistics  ")
sc = tk.Frame(st_tab, bg=BG_DEEP)
sc.pack(fill="both", expand=True, padx=14, pady=14)

stats_card = tk.Frame(sc, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
stats_card.pack(fill="x", pady=(0, 10))
tk.Label(stats_card, text="OVERVIEW", font=("Segoe UI", 10, "bold"),
         fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w", padx=16, pady=(14, 0))
tk.Frame(stats_card, bg=BORDER_COLOR, height=1).pack(fill="x", padx=16, pady=(6, 0))
stats_text = tk.Text(stats_card, font=MONO_FONT, height=6, wrap="word",
                     bg=BG_INPUT, fg=TEXT_PRIMARY, relief="flat", padx=12, pady=10,
                     state="disabled", highlightbackground=BORDER_COLOR,
                     highlightthickness=1)
stats_text.pack(fill="x", padx=16, pady=(8, 16))

br = tk.Frame(sc, bg=BG_DEEP)
br.pack(fill="x", pady=6)
_btn(br, "Refresh", ACCENT_BLUE, refresh_statistics, side="left", padx=4)
_btn(br, "Export CSV", WARN_ORANGE, export_report, side="left", padx=4)
_btn(br, "Clear History", DANGER_RED, clear_history, side="left", padx=4)

hist_card = tk.Frame(sc, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
hist_card.pack(fill="both", expand=True, pady=(6, 0))
tk.Label(hist_card, text="ANALYSIS HISTORY", font=("Segoe UI", 10, "bold"),
         fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w", padx=16, pady=(14, 0))
tk.Frame(hist_card, bg=BORDER_COLOR, height=1).pack(fill="x", padx=16, pady=(6, 0))
history_view = tk.Text(hist_card, font=MONO_FONT, height=16, wrap="word",
                       bg=BG_INPUT, fg=TEXT_PRIMARY, relief="flat", padx=12, pady=10,
                       state="disabled", highlightbackground=BORDER_COLOR,
                       highlightthickness=1)
history_view.pack(fill="both", expand=True, padx=16, pady=(8, 16))
```

- [ ] **Step 2: Update Quarantine tab widget colors**

```python
# ── TAB 3: QUARANTINE ─────────────────────────────────────────────────────────
qt_tab = tk.Frame(notebook, bg=BG_DEEP)
notebook.add(qt_tab, text="  Quarantine  ")
qc = tk.Frame(qt_tab, bg=BG_DEEP)
qc.pack(fill="both", expand=True, padx=14, pady=14)

qbr = tk.Frame(qc, bg=BG_DEEP)
qbr.pack(fill="x", pady=(0, 10))
_btn(qbr, "Refresh", ACCENT_BLUE, show_quarantine, side="left", padx=4)
_btn(qbr, "Delete File", DANGER_RED, delete_quarantine_file, side="left", padx=4)

q_card = tk.Frame(qc, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
q_card.pack(fill="both", expand=True)
tk.Label(q_card, text="QUARANTINED FILES", font=("Segoe UI", 10, "bold"),
         fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w", padx=16, pady=(14, 0))
tk.Frame(q_card, bg=BORDER_COLOR, height=1).pack(fill="x", padx=16, pady=(6, 0))
quarantine_view = tk.Text(q_card, font=MONO_FONT, height=20, wrap="word",
                          bg=BG_INPUT, fg=TEXT_PRIMARY, relief="flat", padx=12, pady=10,
                          state="disabled", highlightbackground=BORDER_COLOR,
                          highlightthickness=1)
quarantine_view.pack(fill="both", expand=True, padx=16, pady=(8, 16))
```

- [ ] **Step 3: Update `delete_quarantine_file` Toplevel dialog**

In `delete_quarantine_file`, replace the dialog styling:

```python
    sel_win.config(bg=BG_CARD)
    tk.Label(sel_win, text="Select file to delete:", font=HEADER_FONT,
             bg=BG_CARD, fg=TEXT_PRIMARY).pack(pady=(16, 8))
    listbox = tk.Listbox(sel_win, font=MONO_FONT, height=12, selectmode="single",
                         bg=BG_INPUT, fg=TEXT_PRIMARY, relief="flat",
                         selectbackground=ACCENT_BLUE, selectforeground="white",
                         highlightbackground=BORDER_COLOR, highlightthickness=1)
    # ...
    btn_frame = tk.Frame(sel_win, bg=BG_CARD)
    # DELETE button: bg=DANGER_RED; Cancel button: bg=BG_INPUT, fg=TEXT_MUTED
```

- [ ] **Step 4: Full smoke test**

```
python main.py
```
Check all three tabs. Expected: all dark backgrounds, muted labels, consistent border colors throughout.

- [ ] **Step 5: Commit**

```
git add app/main.py
git commit -m "refactor: apply dark theme to Statistics, Quarantine tabs and dialogs"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Covered in task |
|---|---|
| Dark/Cyber palette (`#0d1117`, `#161b22`, etc.) | Task 1 |
| Title bar: red dot + blue name + green ACTIVE badge | Task 3 |
| Tab bar: blue active tab, muted inactive | Task 2 |
| File row: path entry + Browse + Scan buttons | Task 4 |
| Progress bar: dark card, gradient fill, info label | Task 4 |
| Verdict card ransomware: red bg, ⚠, score, CVSS, buttons | Task 4 |
| Verdict card benign: green bg, ✓, score, CVSS | Task 4 |
| Metrics panel: progress bars per signal | Task 4 |
| IOC badge chips with severity colors | Task 5 |
| Action status green row | Task 5 |
| Scan history footer: colored dots, session count | Task 3 |
| Idle state: placeholder shown before first scan | Task 4/5 |
| State transitions: idle→scanning→result card swap | Task 5 |

**Placeholder scan:** No TBD/TODO present.

**Type consistency:** `bar_value_vars`, `bar_fills`, `verdict_score_var`, `benign_score_var` all defined in Task 4 and consumed in Task 5. `_show_ransomware_card`, `_show_benign_card`, `_hide_verdict_cards` defined in Task 5 before use.

**Ambiguity resolved:** `start_analysis` is wired to both Browse and Scan buttons (Browse opens file dialog; separate Browse-only path was unnecessary complexity — YAGNI).
