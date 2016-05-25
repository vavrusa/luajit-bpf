#/bin/bash -e
pkg="libelf-0.8.13"
if [ ! -f $HOME/.local/lib/pkgconfig/libelf.pc ]; then
	curl -O http://www.mr511.de/software/${pkg}.tar.gz
	tar xvzf ${pkg}.tar.gz
	cd ${pkg}
	./configure --prefix=$HOME/.local
	make
	make install
fi
