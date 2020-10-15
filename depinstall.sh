#!/bin/bash
# Copyright (C) 2020 Shahar Paz <shaharps [at] tau [dot] ac [dot] il>

# This file is part of the CRISP code.
# See <https://github.com/shapaz/CRISP>.

# This file may be used under the terms of the GNU General Public License
# version 3 as published by the Free Software Foundation and appearing in
# the file LICENSE.GPL included in the packaging of this file.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# libsodium
wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
tar -xvf LATEST.tar.gz
rm LATEST.tar.gz
pushd libsodium-stable
make -j
make -j check
sudo make install
popd

# For MCL and BPC
sudo apt install libgmp-dev

# MCL
git clone git://github.com/herumi/mcl
pushd mcl
make -j
sudo make install
sudo cp lib/* /usr/local/lib/
popd

# PBC
# TODO
