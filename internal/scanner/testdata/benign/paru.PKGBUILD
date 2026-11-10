# Maintainer: Morganamilo <morganamilo@archlinux.org>
pkgname=paru
pkgver=2.0.4
pkgrel=1
pkgdesc="AUR helper and pacman wrapper"
arch=('x86_64')
url="https://github.com/Morganamilo/paru"
license=('GPL-3.0-or-later')
depends=('git' 'pacman' 'libalpm.so')
makedepends=('cargo')
conflicts=('paru-git')
source=("$pkgname-$pkgver.tar.gz::https://github.com/Morganamilo/paru/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

prepare() {
  cd "$srcdir/$pkgname-$pkgver"
  cargo fetch --locked --target "$CARCH-unknown-linux-gnu"
}

build() {
  cd "$srcdir/$pkgname-$pkgver"
  cargo build --frozen --release
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  install -Dm755 "target/release/paru" "$pkgdir/usr/bin/paru"
}
