#!/usr/bin/env python3
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

from argparse import ArgumentParser, Action
from subprocess import Popen, PIPE
from collections import OrderedDict
from os import chdir, wait, isatty
from math import floor, ceil
from sys import stdout
from time import time

PROC = 0
FILE = 1
PEER = 2
KEY  = 3

def style( *specs ):
	STYLES = ('normal','bold','dim','italic','underline')
	COLORS = ('BLACK','RED','GREEN','YELLOW','BLUE','MAGENTA','CYAN','WHITE')
	colors = [ c.lower() for c in COLORS ]
	def _get( colors, c, background ):
		return 10*background + colors.index(c)
	l = []
	for i,s in enumerate(specs):
		if s in colors:
			x = colors.index(s) + (i%2)*10 + 30
		elif s in COLORS:
			x = COLORS.index(s) + (i%2)*10 + 90
		elif s.lower() in STYLES:
			x = STYLES.index( s.lower() )
		else:
			continue
		l.append( str(x) )
	return '\x1b[' + ';'.join(l) + 'm'

COLOR_TITLE = style( 'WHITE', 'black', 'underline' )
COLOR_EVEN  = style( 'WHITE', 'blue', 'bold' )
COLOR_ODD   = style( 'black', 'BLUE', 'bold', 'dim' )
COLOR_RESET = style()


def Percentile( a, p ):
	f = float(p) * len(a)
	i = int(f)
	if i == len(a):
		return a[-1]
	if f.is_integer():
		return a[i]
	v = a[i:i+1]
	return ( min(v) + max(v) ) / 2

def Transpose(tbl):
	return [ [ tbl[i][j] for i in range(len(tbl)) ] for j in range(len(tbl[0])) ]

def Table( title, sub_title, unit, rows ):
	width = [ max(len(name)+2 for name in rows) ] + [ len(t)+1 for t in title ] + [ max(len(t)+2 for t in sub_title), len(unit)+1 ]
	for sub_rows in rows.values():
		for cols in sub_rows:
			for j, col in enumerate(cols):
				width[j+1] = max( width[j+1], len(col)+1 )

	print( COLOR_TITLE + ''.join('{:>{width}s}'.format(t, width=w) for w,t in zip(width,['']+title+['',''])) + COLOR_RESET )
	odd = True
	for name, sub_rows in rows.items():
		odd = not odd
		for i, cols in enumerate(sub_rows):
			print( COLOR_ODD if odd else COLOR_EVEN, end='' )
			print( '{:<{width}s}'.format(name if i==0 else '', width=width[0]), end='' )
			for j,col in enumerate(cols+[sub_title[i], unit]):
				print( '{:>{width}s}'.format(col, width=width[j+1]), end='' )
			print( COLOR_RESET )


if __name__ == '__main__':
	parser = ArgumentParser()
	parser.add_argument('protocol', default='CRISP', choices=['CRISP','CHIP'], nargs='?', help='the protocol to test')
	parser.add_argument('-n', '--count', type=int, default='1000', help='number of iterations')
	parser.add_argument('-ip', help='IP address of the remote peer')
	parser.add_argument('--color', default='auto', choices=['always','never','auto'], help='show colors')
	class Extend(Action):
		def __call__(self, parser, namespace, lst, *args):
			getattr(namespace, self.dest).extend(lst)
	parser.add_argument('-p','--percentiles', type=int, nargs='*', default=[], action=Extend, help='percentiles to show')
	args = parser.parse_args()
	if args.color == 'never' or ( args.color == 'auto' and not isatty(stdout.fileno()) ):
		COLOR_TITLE = COLOR_EVEN = COLOR_ODD = COLOR_RESET = ''
	chdir( args.protocol )
	times = OrderedDict()
	if args.ip:
		parties = ([None, 'alice.pwd', None, None],)
	else:
		parties = ([None, 'alice.pwd', 'Bob', None], [None, 'bob.pwd','Alice', None])
	print( 'Measuring {} over {} iterations:'.format(args.protocol, args.count) )

	for i in range(args.count):
		port = str(8000 + i % (2000))
		port = [port] if args.ip is None else [args.ip, port]
		stdout.write('\r{:>6.2%} {:6} '.format(float(i)/args.count, i))
		stdout.flush()
		for p in parties:
			p[PROC] = Popen(['./key_exchange', p[FILE]] + port, stdout=PIPE)
		fail = False
		stop = False
		for j in range(len(parties)):
			try:
				pid, status = wait()
			except KeyboardInterrupt:
				for p in parties:
					p[PROC].terminate()
				print('User interrupt')
				while True:
					decision = raw_input('Stop? (y/N) ').lower()
					if decision in ['y','yes']:
						stop = True
						break
					elif decision in ['','n','no']:
						fail = True
						break
				break
			if status != 0:
				for p in parties:
					if p[PROC].pid != pid:
						p[PROC].terminate()
				print( 'Process {} failed with {}'.format(pid, status) )
				fail = True
				break
		if stop:
			break
		if fail:
			continue
		for p in parties:
			output = map( bytes.decode, p[PROC].stdout.readlines() )
			header = next(output).split()
			lines = OrderedDict( map( str.strip, line.split(':') ) for line in output if ':' in line )
			identified = lines.get('Identified')
			p[KEY] = lines.get('Shared key')
			if p[PEER] is not None:
				assert identified == p[PEER], 'Expected {} but got {}'.format(p[PEER], identified)
			for k,v in lines.items():
				if v.endswith((' s', ' ms', ' us', ' ns')):
					mul = 1000 ** 'num '.find(v[-2])
					values = v[:-3].split()
					a = times.setdefault( k, tuple([] for t in values) )
					for i,t in enumerate( values ):
						a[i].append( float(t)*mul )
		if len(parties) == 2:
			assert parties[0][KEY] == parties[1][KEY]
	stdout.write('\r')

	percents = [p/100 for p in sorted(args.percentiles or [50])]
	p_title = ['{:.0%}'.format(p) for p in percents]
	h_title = header[1:]
	flip = len(p_title) > len(h_title)

	d = OrderedDict()
	for k, categories in times.items():
		row = []
		for cat in categories:
			cat = sorted(cat)
			sub_row = []
			for i, p in enumerate(percents):
				sub_row.append( str(int( Percentile(cat,p)/1000 )) )
			row.append( sub_row )
		d[k] = row if flip else Transpose(row)
	Table( p_title if flip else h_title, h_title if flip else p_title, 'us', d )