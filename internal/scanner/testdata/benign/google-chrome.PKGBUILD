# Maintainer: Google <chrome@example.com>
pkgname=google-chrome
pkgver=120.0.6099.109
pkgrel=1
pkgdesc="The popular web browser by Google"
arch=('x86_64')
url="https://www.google.com/chrome/"
license=('custom:chrome')
depends=('gtk3' 'nss' 'alsa-lib' 'libxss' 'libcups')
source=("https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb")
sha256sums=('8f6e0a4a1c0e4b6d9a0e1b7f0a2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5')

package() {
  bsdtar -xf "$srcdir/google-chrome-stable_current_amd64.deb" -C "$srcdir"
  install -Dm755 "$srcdir/opt/google/chrome/google-chrome" "$pkgdir/opt/google/chrome/google-chrome"
  install -Dm644 "$srcdir/usr/share/applications/google-chrome.desktop" "$pkgdir/usr/share/applications/google-chrome.desktop"
}
