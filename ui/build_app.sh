#!/bin/bash
# 把 SecForge 打包成真正的 macOS App (带图标, 可放启动台/程序坞)
# 用法: bash ui/build_app.sh
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="/tmp/secforge_app_build"
APPNAME="SecForge"

echo "① 画图标 ..."
mkdir -p "$BUILD"
cat > "$BUILD/mkicon.py" <<'PYEOF'
from PIL import Image, ImageDraw, ImageFont

S = 1024
BG      = (20, 27, 23, 255)      # 深底
BAND    = (24, 33, 28, 255)
BORDER  = (43, 58, 49, 255)
GREEN   = (95, 160, 74, 255)
GREEN_D = (58, 74, 64, 255)
ORANGE  = (224, 123, 43, 255)
TXT     = (216, 226, 219, 255)

img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# 圆角底板
d.rounded_rectangle([40, 40, S - 40, S - 40], radius=210, fill=BG)

# 顶部军绿带(裁剪在圆角内)
band = Image.new("RGBA", (S, S), (0, 0, 0, 0))
bd = ImageDraw.Draw(band)
bd.rectangle([40, 40, S - 40, 190], fill=BAND)
bd.rectangle([40, 188, S - 40, 196], fill=GREEN)
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([40, 40, S - 40, S - 40], radius=210, fill=255)
img.paste(band, (0, 0), mask)

# 外描边
d.rounded_rectangle([48, 48, S - 48, S - 48], radius=204, outline=BORDER, width=10)

# 六边形盾
def hexa(cy_top, cy_bot, half, inset=0):
    cy = (cy_top + cy_bot) / 2
    return [(512, cy_top), (512 + half, cy_top + (cy - cy_top) * 0.52),
            (512 + half, cy_bot - (cy_bot - cy) * 0.52), (512, cy_bot),
            (512 - half, cy_bot - (cy_bot - cy) * 0.52),
            (512 - half, cy_top + (cy - cy_top) * 0.52)]

outer = hexa(250, 738, 212)
inner = hexa(300, 688, 168)
d.polygon(inner, fill=(14, 20, 17, 255))
d.line(outer + [outer[0]], fill=GREEN, width=26, joint="curve")
d.line(inner + [inner[0]], fill=BORDER, width=6, joint="curve")

# SF 字样
try:
    f = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 208, index=1)
except Exception:
    f = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 208)
bb = d.textbbox((0, 0), "SF", font=f)
d.text((512 - (bb[2] - bb[0]) / 2 - bb[0], 430 - bb[1]), "SF", font=f, fill=TXT)

# 战术橙分隔 + 扫描线
d.rounded_rectangle([392, 596, 632, 608], radius=6, fill=ORANGE)
d.rounded_rectangle([392, 632, 632, 640], radius=4, fill=GREEN_D)
d.rounded_rectangle([392, 656, 560, 664], radius=4, fill=GREEN_D)
d.rounded_rectangle([392, 680, 488, 688], radius=4, fill=GREEN)

img.save("/tmp/secforge_icon_1024.png")
print("   图标 PNG 完成 1024x1024")

# iconset
import os
os.makedirs("/tmp/secforge.iconset", exist_ok=True)
for base in (16, 32, 128, 256, 512):
    for scale, suffix in ((1, ""), (2, "@2x")):
        px = base * scale
        img.resize((px, px), Image.LANCZOS).save(f"/tmp/secforge.iconset/icon_{base}x{base}{suffix}.png")
print("   iconset 完成:", len(os.listdir('/tmp/secforge.iconset')), "个尺寸")
PYEOF
/usr/bin/python3 "$BUILD/mkicon.py"

echo "② 生成 .icns ..."
rm -f "$BUILD/SecForge.icns"
iconutil -c icns /tmp/secforge.iconset -o "$BUILD/SecForge.icns"
echo "   $(ls -la "$BUILD/SecForge.icns" | awk '{print $5}') 字节"

echo "③ 组装 App ..."
APP="$BUILD/$APPNAME.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BUILD/SecForge.icns" "$APP/Contents/Resources/"
cp "$ROOT/ui/app_launcher.sh" "$APP/Contents/MacOS/$APPNAME"
chmod +x "$APP/Contents/MacOS/$APPNAME"

cat > "$APP/Contents/Info.plist" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>SecForge</string>
  <key>CFBundleDisplayName</key><string>SecForge</string>
  <key>CFBundleIdentifier</key><string>com.kangyx.secforge</string>
  <key>CFBundleExecutable</key><string>SecForge</string>
  <key>CFBundleIconFile</key><string>SecForge</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSUIElement</key><true/>
  <key>NSAppleEventsUsageDescription</key><string>启动失败时弹提示用</string>
</dict>
</plist>
PLISTEOF

echo "   验证 plist: $(plutil -lint "$APP/Contents/Info.plist" 2>&1 | tail -1)"

echo "④ 安装 ..."
DEST=""
for d in "/Applications" "$HOME/Applications"; do
  if cp -R "$APP" "$d/" 2>/dev/null; then DEST="$d/$APPNAME.app"; break; fi
done
if [ -z "$DEST" ]; then echo "! 装不上, App 在 $APP"; exit 1; fi
# 刷新图标缓存, 否则可能显示成白纸
touch "$DEST"
/usr/bin/qlmanage -r cache >/dev/null 2>&1 || true
echo "   已安装: $DEST"
echo
echo "完成 ★ 按 F4 打开启动台搜 SecForge, 或双击 $DEST"
