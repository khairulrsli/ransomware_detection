import os
import re


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(ROOT_DIR, "model")
REPORT_DIR = os.path.join(ROOT_DIR, "reports")


def read_text(path):
    with open(path, "r", encoding="utf-8") as file:
        return file.read()


def write_svg(filename, content):
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, filename)
    with open(path, "w", encoding="utf-8") as file:
        file.write(content)
    return path


def parse_evaluation_results():
    text = read_text(os.path.join(MODEL_DIR, "evaluation_results.txt"))

    metrics = {}
    for key in ("Accuracy", "Precision", "Recall", "F1-Score"):
        match = re.search(rf"{key}\s*:\s*([0-9.]+)%", text)
        if match:
            metrics[key] = float(match.group(1))

    cm_match = re.search(
        r"Actual Benign\s+(\d+)\s+(\d+).*?Actual Malicious\s+(\d+)\s+(\d+)",
        text,
        re.S,
    )
    if not cm_match:
        raise ValueError("Could not parse confusion matrix from evaluation_results.txt")

    tn, fp, fn, tp = [int(value) for value in cm_match.groups()]
    return metrics, [[tn, fp], [fn, tp]]


def parse_training_history():
    text = read_text(os.path.join(MODEL_DIR, "training_epochs.txt"))
    rows = []
    pattern = re.compile(
        r"^\s*(\d+)\s+([0-9.]+)\s+([0-9.]+)%\s+([0-9.]+)\s+([0-9.]+)%",
        re.M,
    )
    for match in pattern.finditer(text):
        rows.append(
            {
                "epoch": int(match.group(1)),
                "loss": float(match.group(2)),
                "accuracy": float(match.group(3)),
                "val_loss": float(match.group(4)),
                "val_accuracy": float(match.group(5)),
            }
        )
    return rows


def confusion_matrix_svg(matrix):
    labels_x = ["Predicted Benign", "Predicted Malicious"]
    labels_y = ["Actual Benign", "Actual Malicious"]
    max_value = max(max(row) for row in matrix)
    cells = []

    for y, row in enumerate(matrix):
        for x, value in enumerate(row):
            intensity = int(245 - (value / max_value) * 145)
            fill = f"rgb({intensity},{intensity + 8},{255})"
            text_color = "#111827" if intensity > 140 else "#ffffff"
            x_pos = 220 + x * 210
            y_pos = 155 + y * 150
            cells.append(
                f'<rect x="{x_pos}" y="{y_pos}" width="200" height="140" rx="8" fill="{fill}" stroke="#d1d5db"/>'
                f'<text x="{x_pos + 100}" y="{y_pos + 72}" text-anchor="middle" font-size="36" font-weight="700" fill="{text_color}">{value}</text>'
            )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="720" height="520" viewBox="0 0 720 520">
<rect width="720" height="520" fill="#ffffff"/>
<text x="360" y="48" text-anchor="middle" font-family="Segoe UI, Arial" font-size="26" font-weight="700" fill="#111827">Confusion Matrix</text>
<text x="320" y="110" text-anchor="middle" font-family="Segoe UI, Arial" font-size="16" font-weight="600" fill="#374151">{labels_x[0]}</text>
<text x="530" y="110" text-anchor="middle" font-family="Segoe UI, Arial" font-size="16" font-weight="600" fill="#374151">{labels_x[1]}</text>
<text x="130" y="230" text-anchor="middle" font-family="Segoe UI, Arial" font-size="16" font-weight="600" fill="#374151">{labels_y[0]}</text>
<text x="130" y="380" text-anchor="middle" font-family="Segoe UI, Arial" font-size="16" font-weight="600" fill="#374151">{labels_y[1]}</text>
{''.join(cells)}
<text x="320" y="325" text-anchor="middle" font-family="Segoe UI, Arial" font-size="13" fill="#374151">True Negative</text>
<text x="530" y="325" text-anchor="middle" font-family="Segoe UI, Arial" font-size="13" fill="#374151">False Positive</text>
<text x="320" y="475" text-anchor="middle" font-family="Segoe UI, Arial" font-size="13" fill="#374151">False Negative</text>
<text x="530" y="475" text-anchor="middle" font-family="Segoe UI, Arial" font-size="13" fill="#374151">True Positive</text>
</svg>
"""


def metrics_bar_svg(metrics):
    bars = []
    names = list(metrics.keys())
    for index, name in enumerate(names):
        value = metrics[name]
        bar_height = value * 3
        x = 105 + index * 140
        y = 405 - bar_height
        bars.append(
            f'<rect x="{x}" y="{y:.1f}" width="80" height="{bar_height:.1f}" rx="6" fill="#2563eb"/>'
            f'<text x="{x + 40}" y="{y - 12:.1f}" text-anchor="middle" font-size="16" font-weight="700" fill="#111827">{value:.2f}%</text>'
            f'<text x="{x + 40}" y="435" text-anchor="middle" font-size="15" fill="#374151">{name}</text>'
        )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="720" height="500" viewBox="0 0 720 500">
<rect width="720" height="500" fill="#ffffff"/>
<text x="360" y="48" text-anchor="middle" font-family="Segoe UI, Arial" font-size="26" font-weight="700" fill="#111827">Model Performance Metrics</text>
<line x1="70" y1="405" x2="650" y2="405" stroke="#9ca3af"/>
<line x1="70" y1="105" x2="70" y2="405" stroke="#9ca3af"/>
<text x="55" y="110" text-anchor="end" font-size="12" fill="#6b7280">100%</text>
<text x="55" y="260" text-anchor="end" font-size="12" fill="#6b7280">50%</text>
<text x="55" y="410" text-anchor="end" font-size="12" fill="#6b7280">0%</text>
{''.join(bars)}
</svg>
"""


def training_history_svg(rows):
    width = 840
    height = 520
    left = 70
    top = 80
    chart_w = 700
    chart_h = 330
    max_epoch = max(row["epoch"] for row in rows)

    def point(row, key):
        x = left + ((row["epoch"] - 1) / max(max_epoch - 1, 1)) * chart_w
        y = top + (100 - row[key]) / 100 * chart_h
        return x, y

    train_points = " ".join(f"{x:.1f},{y:.1f}" for x, y in (point(row, "accuracy") for row in rows))
    val_points = " ".join(f"{x:.1f},{y:.1f}" for x, y in (point(row, "val_accuracy") for row in rows))

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="{width}" height="{height}" fill="#ffffff"/>
<text x="{width / 2}" y="48" text-anchor="middle" font-family="Segoe UI, Arial" font-size="26" font-weight="700" fill="#111827">Training Accuracy History</text>
<line x1="{left}" y1="{top + chart_h}" x2="{left + chart_w}" y2="{top + chart_h}" stroke="#9ca3af"/>
<line x1="{left}" y1="{top}" x2="{left}" y2="{top + chart_h}" stroke="#9ca3af"/>
<text x="55" y="{top + 5}" text-anchor="end" font-size="12" fill="#6b7280">100%</text>
<text x="55" y="{top + chart_h / 2 + 5}" text-anchor="end" font-size="12" fill="#6b7280">50%</text>
<text x="55" y="{top + chart_h + 5}" text-anchor="end" font-size="12" fill="#6b7280">0%</text>
<polyline points="{train_points}" fill="none" stroke="#2563eb" stroke-width="3"/>
<polyline points="{val_points}" fill="none" stroke="#dc2626" stroke-width="3"/>
<rect x="250" y="445" width="18" height="4" fill="#2563eb"/>
<text x="276" y="451" font-size="14" fill="#374151">Training Accuracy</text>
<rect x="425" y="445" width="18" height="4" fill="#dc2626"/>
<text x="451" y="451" font-size="14" fill="#374151">Validation Accuracy</text>
<text x="{left + chart_w / 2}" y="485" text-anchor="middle" font-size="14" fill="#374151">Epoch</text>
</svg>
"""


def main():
    metrics, matrix = parse_evaluation_results()
    rows = parse_training_history()

    outputs = [
        write_svg("confusion_matrix.svg", confusion_matrix_svg(matrix)),
        write_svg("model_metrics.svg", metrics_bar_svg(metrics)),
        write_svg("training_accuracy.svg", training_history_svg(rows)),
    ]

    print("Generated charts:")
    for path in outputs:
        print(path)


if __name__ == "__main__":
    main()
