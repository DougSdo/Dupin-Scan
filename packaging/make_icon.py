"""Gera assets/vigil.png e assets/vigil.ico (requer PySide6 e Pillow)."""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication, QImage, QLinearGradient, QPainter, QPainterPath, QPen

app = QGuiApplication(sys.argv)
S = 512
img = QImage(S, S, QImage.Format_ARGB32)
img.fill(Qt.transparent)
p = QPainter(img)
p.setRenderHint(QPainter.Antialiasing)
g = QLinearGradient(0, 0, S, S)
g.setColorAt(0, QColor("#1d4ed8"))
g.setColorAt(1, QColor("#0f172a"))
p.setBrush(QBrush(g))
p.setPen(Qt.NoPen)
p.drawRoundedRect(16, 16, S - 32, S - 32, 110, 110)
shield = QPainterPath()
shield.moveTo(S / 2, 96)
shield.lineTo(392, 146)
shield.lineTo(392, 262)
shield.cubicTo(392, 340, 330, 392, S / 2, 428)
shield.cubicTo(182, 392, 120, 340, 120, 262)
shield.lineTo(120, 146)
shield.closeSubpath()
p.setBrush(QColor(255, 255, 255, 235))
p.drawPath(shield)
pen = QPen(QColor("#1d4ed8"), 30, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
p.setPen(pen)
p.setBrush(Qt.NoBrush)
chk = QPainterPath()
chk.moveTo(190, 258)
chk.lineTo(240, 308)
chk.lineTo(332, 200)
p.drawPath(chk)
p.end()

out = Path(__file__).resolve().parent.parent / "assets"
out.mkdir(exist_ok=True)
img.save(str(out / "vigil.png"))
try:
    from PIL import Image
    Image.open(out / "vigil.png").save(out / "vigil.ico", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
except ImportError:
    print("Pillow ausente: .ico não gerado")
# marca de seleção para checkboxes
c = QImage(36, 36, QImage.Format_ARGB32)
c.fill(Qt.transparent)
q = QPainter(c)
q.setRenderHint(QPainter.Antialiasing)
q.setPen(QPen(QColor("white"), 5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
path = QPainterPath()
path.moveTo(9, 19)
path.lineTo(15, 25)
path.lineTo(27, 11)
q.drawPath(path)
q.end()
c.save(str(out / "check.png"))
print("ícones gerados em", out)
