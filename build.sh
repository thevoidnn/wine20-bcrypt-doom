

pkgname=wine-2.0-rc1

srcdir=`pwd`

function configure64 {
../$pkgname/configure \
    --prefix=/usr     \
    --libdir=/usr/lib \
    --with-x          \
    --with-xattr      \
    --with-gstreamer  \
    --disable-tests   \
    --enable-win64

}

_wine32opts=(
--libdir=/usr/lib32
--with-wine64="$srcdir/$pkgname-64-build"
)

function configure32 {
../$pkgname/configure \
--prefix=/usr         \
--with-x              \
--with-xattr          \
--with-gstreamer      \
--disable-tests       \
"${_wine32opts[@]}"

}

mkdir -p "$srcdir/$pkgname-32-build"
mkdir -p "$srcdir/$pkgname-64-build"

# Build x64

echo "Building Wine-64..."
cd "$srcdir/$pkgname-64-build"

configure64
make -j8
#make

# Build x32

export PKG_CONFIG_PATH="/usr/lib32/pkgconfig"

echo "Building Wine-32..."
cd "$srcdir/$pkgname-32-build"

configure32
make -j8
#make
