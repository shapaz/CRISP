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

.PHONY: all clean crisp chip test

NETWORK  ?= 'My home WiFi'
PASSWORD ?= 'Pa$$$$Word'
PAIRING_LIB ?=MCL
CC       := g++

BINARIES := CRISP/gen_pwd_file CRISP/key_exchange CHIP/gen_pwd_file CHIP/key_exchange
OBJECTS  := $(BINARIES:%=%.o) pake.o utils.o pairing.o
override CXXFLAGS += -std=c++11 -g3 -O3 -Wall -Wextra -pedantic -Wconversion -ffunction-sections -fdata-sections -DPAIRING_LIB=$(PAIRING_LIB) -DUSE_COMPRESSION
override LDFLAGS  += -Wl,--gc-sections
LDLIBS   := -lgmp -lsodium -lrt
ifeq ($(PAIRING_LIB), PBC)
LDLIBS += -lpbc
else ifeq ($(PAIRING_LIB), MCL)
LDLIBS += -lmclbn256 -lmcl
else
$(error "Unsupported PAIRING_LIB")
endif

all: $(BINARIES)

clean:
	rm -f $(BINARIES) $(OBJECTS)

CRISP/gen_pwd_file: CRISP/gen_pwd_file.o pairing.o utils.o
CRISP/key_exchange: CRISP/key_exchange.o pairing.o pake.o utils.o

CHIP/gen_pwd_file: CHIP/gen_pwd_file.o utils.o
CHIP/key_exchange: CHIP/key_exchange.o pake.o utils.o

%/alice.pwd: %/gen_pwd_file
	$< $(NETWORK) $(PASSWORD) Alice > $@

%/bob.pwd: %/gen_pwd_file
	$< $(NETWORK) $(PASSWORD) Bob > $@

%/carol.pwd: %/gen_pwd_file
	$< $(NETWORK) 'WrOnGPwD' Carol > $@

crisp: CRISP/alice.pwd CRISP/bob.pwd CRISP/carol.pwd CRISP/key_exchange
	./test.py CRISP

chip:   CHIP/alice.pwd  CHIP/bob.pwd  CHIP/carol.pwd  CHIP/key_exchange
	./test.py CHIP

test: crisp chip