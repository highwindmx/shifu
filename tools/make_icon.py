"""生成释缚应用图标：圆角矩形、绿底白字、中间一个"解"字。

用 PyQt6 的 QPainter 渲染多尺寸 PNG，再用标准库封装为 PNG 压缩式 ICO
（Vista+ 支持）。无需 Pillow，offscreen 模式无窗口也可运行。
"""
from __future__ import annotations

import os
import struct

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QBuffer, QIODevice, QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QFontDatabase, QImage, QLinearGradient, QPainter, QPen
from PyQt6.QtWidgets import QApplication

SIZES = [16, 24, 32, 48, 64, 128, 256]

# offscreen 模式下 QFontDatabase 可能为空，显式加载系统微软雅黑粗体，
# 否则 QFont("Microsoft YaHei") 找不到字体，"解"字会画成空方框（tofu）。
_BOLD_FONT_FILE = r"C:\Windows\Fonts\msyhbd.ttc"
GREEN = QColor("#1E9E5A")
GREEN_DARK = QColor("#157A45")
WHITE = QColor("#FFFFFF")
_ICON_FONT_FAMILY = "Microsoft YaHei"
_app = None


def render(size: int) -> QImage:
    ss = 4  # 超采样抗锯齿
    s = size * ss
    img = QImage(s, s, QImage.Format.Format_ARGB32)
    img.fill(QColor(0, 0, 0, 0))

    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.TextAntialiasing)

    margin = int(s * 0.06)
    rect = QRectF(margin, margin, s - 2 * margin, s - 2 * margin)
    radius = s * 0.22

    grad = QLinearGradient(0, rect.top(), 0, rect.bottom())
    grad.setColorAt(0.0, GREEN)
    grad.setColorAt(1.0, GREEN_DARK)
    p.setBrush(QBrush(grad))
    p.setPen(QPen(GREEN_DARK, max(1, int(s * 0.012))))
    p.drawRoundedRect(rect, radius, radius)

    font = QFont(_ICON_FONT_FAMILY)
    font.setBold(True)
    font.setPixelSize(int(s * 0.56))
    p.setFont(font)
    p.setPen(QPen(WHITE))
    p.drawText(rect, Qt.AlignmentFlag.AlignCenter, "解")
    p.end()

    return img.scaled(
        size, size, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation
    )


def to_png_bytes(img: QImage) -> bytes:
    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    buf.close()
    return bytes(buf.data())


def main():
    global _ICON_FONT_FAMILY, _app
    # 必须持有 QApplication 引用，否则被 GC 回收后 Qt 内部状态失效导致 segfault
    _app = QApplication([])
    families = QFontDatabase.applicationFontFamilies(
        QFontDatabase.addApplicationFont(_BOLD_FONT_FILE)
    )
    if families:
        _ICON_FONT_FAMILY = families[0]
    out = os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "shifu.ico")
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)

    pngs = [to_png_bytes(render(sz)) for sz in SIZES]

    # PNG 压缩式 ICO 容器
    header = struct.pack("<HHH", 0, 1, len(pngs))
    offset = 6 + 16 * len(pngs)
    entries = b""
    blobs = b""
    for sz, png in zip(SIZES, pngs):
        dim = 0 if sz >= 256 else sz  # 256 在 ICO 中用 0 表示
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        blobs += png
        offset += len(png)

    with open(out, "wb") as f:
        f.write(header + entries + blobs)

    print("图标已生成:", out, os.path.getsize(out), "bytes")
    print("包含尺寸:", SIZES)


if __name__ == "__main__":
    main()
