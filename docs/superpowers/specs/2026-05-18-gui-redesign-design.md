# GUI Redesign — Design Spec
**Date:** 2026-05-18  
**Scope:** `app/main.py` — tkinter GUI only. No changes to detection logic, model, or behavior engine.

---

## Design Decisions

| Question | Choice |
|---|---|
| Theme | Dark/Cyber (GitHub-dark palette) |
| Result display | Verdict + IOCs Split |
| Metrics panel | Visual Dashboard (progress bars + badge chips) |

---

## Color Palette

| Token | Hex | Usage |
|---|---|---|
| `BG_DEEP` | `#0d1117` | Window background |
| `BG_CARD` | `#161b22` | Card / panel backgrounds |
| `BG_INPUT` | `#21262d` | Input fields, progress track |
| `BORDER` | `#30363d` | All card/panel borders |
| `TEXT_PRIMARY` | `#e6edf3` | Primary text |
| `TEXT_MUTED` | `#8b949e` | Labels, secondary text |
| `ACCENT_BLUE` | `#58a6ff` | Accent, scan button, links |
| `DANGER_RED` | `#ff4444` | Ransomware verdict, critical IOCs |
| `WARN_ORANGE` | `#ffa500` | Warning IOCs (RapidWrite, HighEntropy) |
| `SUCCESS_GREEN` | `#3fb950` | Benign verdict, quarantine confirmed |
| `BTN_BLUE` | `#1f6feb` | Primary action button fill |

---

## Layout — Analysis Tab

```
┌─────────────────────────────────────────────────────────┐
│ ● RANSOMWARE DETECTION SYSTEM          [● ACTIVE]        │  ← title bar
├──────────┬─────────────┬──────────────────────────────────┤
│ Analysis │ Statistics  │ Quarantine                        │  ← tab bar
├──────────┴─────────────┴──────────────────────────────────┤
│ [file path input field ................] [Browse] [Scan]  │  ← file row
├────────────────────────────────────────────────────────────┤
│ Behavioral Analysis          847 events · 2.4s            │
│ [████████████████████████████████████████]                │  ← progress bar
├─────────────────┬──────────────────────────────────────────┤
│  VERDICT CARD   │  METRICS PANEL                          │
│  (160px wide)   │  (flex:1)                               │
│                 │                                          │
│  ⚠              │  ML Confidence         93.4%            │
│  RANSOMWARE     │  ─ ML Score    ████░░  0.934            │
│  DETECTED       │  ─ Write Ops   ████░░  142              │
│                 │  ─ Rapid Write ██░░░░  4                │
│  Threat: 0.847  │  ─ Busy Loops  ██░░░░  7                │
│  CVSS 8.5 HIGH  │  ─ Network     █░░░░░  2                │
│                 │  ─────────────────────────────────────   │
│  [QUARANTINE]   │  IOC INDICATORS                         │
│  [  DELETE  ]   │  [RapidWrite×4] [HighEntropy×2]        │
│                 │  [Canary×1]     [BusyLoop×7]            │
│                 │  ✓ Process killed · Files quarantined   │
├─────────────────┴──────────────────────────────────────────┤
│ SCAN HISTORY                                               │
│ ● suspicious.exe  ● normal.exe  ● notepad.exe             │  ← footer
└────────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

### 1. Title Bar
- Dark `#161b22` strip with 1px bottom border `#30363d`
- Red dot indicator (●, `#ff4444`) + app name in `#58a6ff` bold
- "● ACTIVE" badge (green pill) flush right

### 2. Tab Bar
- Active tab: `#58a6ff` text + 2px bottom border in `#58a6ff`
- Inactive tabs: `#8b949e` text, no border
- Background: `#0d1117`

### 3. File Row
- Path field: `#161b22` bg, `#30363d` border, `#e6edf3` monospace text, rounded 6px
- Browse button: `#21262d` bg, `#30363d` border
- Scan button: `#1f6feb` bg, `#388bfd` border, white bold text

### 4. Progress Bar
- Container card: `#161b22` bg, `#30363d` border, 6px radius
- Label row: left "Behavioral Analysis", right shows event count + elapsed time in `#58a6ff`
- Track: `#21262d`, 5px height, 4px radius
- Fill: gradient `#58a6ff → #1f6feb`, animates left→right during scan

### 5. Verdict Card (ransomware state)
- 160px fixed width, `#1a0000` bg, `#ff4444` border, red glow `box-shadow`
- ⚠ icon (22px), "RANSOMWARE" + "DETECTED" labels
- Threat score (large, `#ff4444`)
- CVSS badge: `#2a0000` bg, orange text for score + severity label
- QUARANTINE button: `#161b22` bg, blue text
- DELETE button: `#1a0000` bg, `#ff4444` border, red text

### 5b. Verdict Card (benign state)
- `#0f3d1f` bg, `#238636` border, green glow
- ✓ icon, "SAFE" + "BENIGN" labels
- Low threat score in `#3fb950`
- CVSS badge shows low/none

### 6. Metrics Panel
- `#161b22` bg, `#30363d` border, flex:1
- Top row: "ML Confidence" label + large % value
- Five progress bars (ML Score, Write Ops, Rapid Writes, Busy Loops, Network Conn)
  - Each bar: label left, value right, 4px track, colored fill
  - Colors: red for ML/threat signals, orange for write signals, blue for network/misc
- Divider `#30363d`
- IOC badges section: pill chips with colored backgrounds matching severity
  - Critical (Canary): `#3d0000` bg, `#ff4444` text/border
  - Warning (RapidWrite, HighEntropy): `#3d1a00` bg, `#ffa500` text/border
  - Info (BusyLoop, etc.): `#21262d` bg, `#8b949e` text/border
- Action status row: green pill "✓ Process killed · Files quarantined"

### 7. Scan History Footer
- `#161b22` bg, `#30363d` border
- "SCAN HISTORY" label in muted uppercase
- Inline colored dots: red for ransomware hits, green for benign
- Right-aligned session count

---

## State Transitions

| Scan State | Verdict Card | Metrics Panel | Progress Bar |
|---|---|---|---|
| Idle | Hidden / placeholder | Hidden | Empty |
| Scanning | Hidden | Live-updating bars | Animated fill |
| Ransomware | Red card, ⚠ | Final values + red IOC badges | Full, static |
| Benign | Green card, ✓ | Final values + low/no IOC badges | Full, static |

---

## Implementation Scope

- **File:** `app/main.py` only
- **Approach:** Replace existing tkinter widget configuration. Keep all existing widget variables, callbacks, and threading logic. Only change colors, fonts, padding, and layout geometry.
- **No new dependencies.** Pure tkinter — no ttk themes that require platform-specific installs.
- **Progress bar animation:** Use `after()` polling on a `tk.DoubleVar` already present; color the fill frame instead of ttk.Progressbar widget.
- **IOC badges:** Replace the existing `Text` widget in the metrics panel with a frame containing dynamically created `Label` pill widgets, cleared and rebuilt on each scan result.
- **Verdict card:** Two pre-built frames (ransomware / benign), swapped via `pack_forget` / `pack` on result.

---

## Out of Scope

- Statistics tab redesign (separate effort)
- Quarantine tab redesign (separate effort)
- Any changes to `behavior_logger.py`, `detection_config.py`, or model files
- New features (real-time streaming score display, animated IOC alerts, etc.)
