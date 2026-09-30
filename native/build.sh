#!/bin/bash
# 把 SecForge 编译成真正的 macOS .app（原生 SwiftUI 程序，不是脚本、不依赖浏览器）
set -e
cd "$(dirname "$0")"

echo "==> 编译 (release)"
swift build -c release 2>&1 | tail -25

BIN=".build/release/SecForge"
[ -x "$BIN" ] || { echo "编译失败"; exit 1; }

APP="/Applications/SecForge.app"

# 老的网页版备份改名，别丢
if [ -d "$APP" ]; then
  if grep -q "Bourne-Again shell script" <(file "$APP/Contents/MacOS/SecForge" 2>/dev/null) 2>/dev/null; then
    echo "==> 老的（网页壳）版本改名成 SecForge-网页版.app，保留着"
    rm -rf /Applications/SecForge-网页版.app
    mv "$APP" /Applications/SecForge-网页版.app
  fi
fi

echo "==> 组装 $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/SecForge"
chmod +x "$APP/Contents/MacOS/SecForge"

# 图标：沿用之前那个（若有）
for src in "./SecForge.icns" "/Applications/SecForge-网页版.app/Contents/Resources/SecForge.icns"; do
  if [ -f "$src" ]; then cp "$src" "$APP/Contents/Resources/SecForge.icns"; break; fi
done

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>SecForge</string>
  <key>CFBundleDisplayName</key><string>SecForge</string>
  <key>CFBundleExecutable</key><string>SecForge</string>
  <key>CFBundleIdentifier</key><string>com.kangyx.secforge.native</string>
  <key>CFBundleIconFile</key><string>SecForge</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>2.0</string>
  <key>CFBundleVersion</key><string>2</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
</dict>
</plist>
PLIST

echo "==> 签名 (ad-hoc)"
codesign --force --deep --sign - "$APP" 2>&1 | tail -3 || echo "(签名跳过，不影响运行)"

echo
echo "完成 → $APP"
file "$APP/Contents/MacOS/SecForge"
du -sh "$APP"
