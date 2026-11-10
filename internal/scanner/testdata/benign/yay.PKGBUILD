# Maintainer: Jguer <jguer@archlinux.org>
pkgname=yay
pkgver=12.1.3
pkgrel=1
pkgdesc="Yet another yogurt. Pacman wrapper and AUR helper written in go."
arch=('x86_64')
url="https://github.com/Jguer/yay"
license=('GPL-3.0-or-later')
depends=('pacman' 'git')
makedepends=('go')
provides=('yay-git')
conflicts=('yay-git')
source=("$pkgname-$pkgver.tar.gz::https://github.com/Jguer/yay/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
  cd "$srcdir/$pkgname-$pkgver"
  go build -mod=vendor -o yay ./cmd/yay
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  install -Dm755 "yay" "$pkgdir/usr/bin/yay"
}
