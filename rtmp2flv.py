#!/usr/bin/python3

import sys, struct, io, collections, logging, argparse

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

parser = argparse.ArgumentParser(description='Extract FLV video from unencrypted RTMP streams.')
parser.add_argument('files', metavar='FILE', nargs='+',
	help='the files to convert (specify "-" to read from stdin and write to stdout)')
parser.add_argument('-s', '--skip', type=int, default=0,
	help='number of bytes to skip at the start of each file')
parser.add_argument('-c', '--chunksize', type=int, default=128,
	help='initial chunk size (you will usually need to provide this when the handshake is missing)')
parser.add_argument('-q', '--quiet', action='store_true',
	help='only show warning and error messages')

def main(args):
	if args.quiet: log.setLevel(logging.WARNING)
	for fn in args.files:
		try:
			convert_file(fn, args)
		except Exception:
			log.exception('Error processing %r', fn)

Message = collections.namedtuple('Message', 'timestamp type streamid data')

def read(f, s):
	return struct.unpack(s, f.read(struct.calcsize(s)))
def r24(f):
	a, b, c = f.read(3)
	return a << 16 | b << 8 | c

def convert_file(fn, args):
	with sys.stdin.buffer if fn == '-' else open(fn, 'rb') as f:
		log.info('Reading from %r', f.name)
		if args.skip: f.seek(args.skip)

		version, = f.read(1)
		if version == 3:
			serveruptime, *serverversion = read(f, '>IBBBB')
			upm, ups = divmod(serveruptime/1E3, 60)
			uph, upm = divmod(upm, 60)
			upd, uph = divmod(uph, 24)
			log.debug('Server uptime: %id %ih %im %0.3fs, version: %i.%i.%i.%i',
				upd, uph, upm, ups, *serverversion)
			f.read(3064)
		else:
			if version == 6: log.error('Encrypted stream')
			else: log.error('Bad RTMP version %i', version)
			log.warn('Bad or missing handshake; trying to continue. '
				'If this does not work, try specifying --chunksize and/or --skip.')
			f.seek(args.skip)

		flvs = {}
		prevts = {}
		try:
			for m in read_rtmp_messages(f, args.chunksize):
				d = m.timestamp - prevts.get((m.streamid, m.type), 0)
				if d < 0:
					log.warn('Timestamp moving backwards! stream=%i, type=%i, d=%i, from %i to %i',
						m.streamid, m.type, d, m.timestamp-d, m.timestamp)
				elif d > 2000:
					log.warn('Timestamp jumping forwards! stream=%i, type=%i, d=%i, from %i to %i',
						m.streamid, m.type, d, m.timestamp-d, m.timestamp)
				prevts[m.streamid, m.type] = m.timestamp
				try:
					flv = flvs[m.streamid]
				except KeyError:
					flvs[m.streamid] = flv = (sys.stdout.buffer if fn == '-'
						else open('%s.%i.flv' % (fn, m.streamid), 'wb'))
					log.info('Writing to %r', flv.name)
					flv.write(FLV_HEADER)
				for buf in get_flv_data(m): flv.write(buf)
		finally:
			for flv in flvs.values(): flv.close()

FLV_HEADER = b'FLV\1\5\0\0\0\x09\0\0\0\0'

def get_flv_data(msg):
	yield struct.pack('>BHBHBB', msg.type,
		len(msg.data) >> 8, len(msg.data) & 0xff,
		(msg.timestamp >> 8) & 0xffff, msg.timestamp & 0xff, msg.timestamp >> 24)
	yield b'\0\0\0' # stream id
	yield msg.data
	yield struct.pack('>I', len(msg.data)+11)

class Stream:
	def __init__(self):
		self.timestamp = self.type = self.streamid = self.data = self.timedelta = self.size = None
		self.bytes_left = 0

def read_rtmp_messages(f, chunksize):
	streams = {}
	while True:
		head = f.read(1)
		if not head: break
		fmt = head[0] >> 6
		csid = head[0] & 0x3f
		if csid == 0: csid = f.read(1)[0] + 64
		elif csid == 1: csid = read(f, '<H')[0] + 64

		try:
			s = streams[csid]
		except KeyError:
			log.debug('New chunk stream %i', csid)
			streams[csid] = s = Stream()

		if fmt != 3:
			s.timedelta = r24(f)
			if s.bytes_left:
				log.warn('Incomplete message')
				s.bytes_left = 0

			if fmt != 2:
				s.size = r24(f)
				s.type, = f.read(1)
				if s.type not in (1,2,3,4,5,6, 8,9, 15,16,17,18,19,20, 22):
					log.warn('Unknown message type %i', s.type)

				if fmt == 0:
					s.streamid, = read(f, '<I')
					s.timestamp = 0
		
		if s.size is None:
			raise Exception('Unknown message size, cannot proceed')
		if s.timestamp is None:
			log.warn('Missing timestamp, assuming 0')
			s.timestamp = 0
		if s.streamid is None:
			log.warn('Missing stream id, assuming 1')
			s.streamid = 1

		if s.bytes_left == 0:
			s.data = []
			s.bytes_left = s.size
			s.timestamp += s.timedelta

		# contrary to spec, extended timestamp is also present for fmt 3
		if s.timedelta == 0xffffff:
			s.timestamp, = read(f, '>I')
				
		data = f.read(min(chunksize, s.bytes_left))
		s.data.append(data)
		s.bytes_left -= len(data)

		if s.bytes_left == 0:
			data = b''.join(s.data)
			s.data = []
			if s.type == 1:
				chunksize, = struct.unpack('>I', data)
				log.info('Set chunk size %i', chunksize)
			elif s.type == 4:
				eventtype, val = struct.unpack('>HI', data)
				if eventtype == 0: log.debug('User control: stream %i begin', val)
				elif eventtype == 1: log.debug('User control: stream %i EOF', val)
				elif eventtype == 2: log.debug('User control: stream %i dry', val)
				elif eventtype == 4: log.debug('User control: stream %i is recorded', val)
				elif eventtype in (6,31,32): pass # PingRequest, BufferEmpty, BufferReady
				else: log.debug('Unhandled user control message %i %i', eventtype, val)
			elif s.type in (5,6): # window ack size, set peer bw
				pass
			elif s.type in (8,9): # audio/video
				if data: yield Message(timestamp=s.timestamp, type=s.type, streamid=s.streamid, data=data)
			elif s.type == 18:
				log.info('Stream %i AMF0 data: %r', s.streamid, AMF0.parse(data))
			elif s.type == 20:
				log.info('Stream %i AMF0 command: %r', s.streamid, AMF0.parse(data))
			elif s.type == 22: # aggregate
				g = io.BytesIO(data)
				firstts = None
				while g.tell() < len(data):
					msgtype, = g.read(1)
					size = r24(g)
					timestamp = r24(g) | g.read(1)[0] << 24
					streamid = r24(g)
					subdata = g.read(size)
					totalsize, = read(g, '>I')
					if totalsize != size: log.warn('Bad footer: expected %i, got %i', size, totalsize)
					if firstts is None: firstts = timestamp
					if msgtype in (8,9): yield Message(timestamp=timestamp-firstts+s.timestamp, type=msgtype, streamid=streamid, data=subdata)
					else: log.warn('Non-AV message type (%i) inside aggregate message', msgtype)
			else: log.debug('Unhandled message type %i', s.type)

class AMF0:
	def parse(data):
		f = io.BytesIO(data)
		decoded = []
		objects = []
		try:
			while f.tell() < len(data): decoded.append(AMF0.read(f, objects))
		except Exception:
			log.exception('Error decoding AMF0 data')
		return decoded

	def read_str(f, sz):
		return f.read(*read(f, sz)).decode('utf8', 'replace')

	def read(f, objects):
		t, = f.read(1)
		if t == 0: return read(f, '>d')[0]
		if t == 1: return bool(*f.read(1))
		if t == 2: return AMF0.read_str(f, '>H')
		if t in (3,8,16):
			if t == 8: f.read(4)
			if t == 16: cls = AMF0.read_str(f, '>H')
			obj = {}
			while True:
				name = AMF0.read_str(f, '>H')
				val = AMF0.read(f, objects)
				if val is StopIteration: break
				obj[name] = val
			if t == 16: obj = cls, obj
			objects.append(obj)
			return obj
		if t == 4: return 'MovieClip', AMF0.read_str(f, '>H')
		if t in (5,6): return None
		if t == 7: return objects[read(f, '>H')[0]]
		if t == 9: return StopIteration
		if t == 10:
			array = [AMF0.read(f, objects) for _ in range(*read(f, '>I'))]
			objects.append(array)
			return array
		if t == 11: return ('Date',) + read(f, '>dH')
		if t == 12: return AMF0.read_str(f, '>I')
		if t == 15: return 'XMLDocument', AMF0.read_str(f, '>I')
		raise Exception('Unhandled type %i at 0x%x' % (t, f.tell()-1))

if __name__ == '__main__': main(parser.parse_args())

