#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from decimal import Decimal
import threading, time, Queue, os, sys, shutil
from math import pow as dec_pow
from util import user_dir, appdata_dir, print_msg, print_msg
from bitcoin import *

try:
    from ltc_scrypt import getPoWHash
except ImportError:
    print_msg("Warning: ltc_scrypt not available, using fallback")
    from scrypt import scrypt_1024_1_1_80 as getPoWHash

KGW_headers = [{} for x in xrange(201)]
Kimoto_vals = [1 + (0.7084 * dec_pow((Decimal(x+1)/Decimal(30)), -1.228)) for x in xrange(201)]
	

class Blockchain(threading.Thread):

    def __init__(self, config, network):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.network = network
        self.lock = threading.Lock()
        self.local_height = 0
        self.running = False
        self.headers_url = 'http://tk.9mmo.com/electrum/blockchain_headers'
        self.set_local_height()
        self.queue = Queue.Queue()

    
    def height(self):
        return self.local_height


    def stop(self):
        with self.lock: self.running = False


    def is_running(self):
        with self.lock: return self.running


    def run(self):
        self.init_headers_file()
        self.set_local_height()
        print_msg( "blocks:", self.local_height )

        with self.lock:
            self.running = True

        while self.is_running():

            try:
                result = self.queue.get()
            except Queue.Empty:
                continue

            if not result: continue

            i, header = result
            if not header: continue
            
            height = header.get('block_height')

            if height <= self.local_height:
                continue

            if height > self.local_height + 50:
                if not self.get_and_verify_chunks(i, header, height):
                    continue

            if height > self.local_height:
                # get missing parts from interface (until it connects to my chain)
                chain = self.get_chain( i, header )

                # skip that server if the result is not consistent
                if not chain: 
                    print_msg('e')
                    continue
                
                # verify the chain
                if self.verify_chain( chain ):
                    print_msg("height:", height, i.server)
                    for header in chain:
                        self.save_header(header)
                else:
                    print_msg("error", i.server)
                    # todo: dismiss that server
                    continue


            self.network.new_blockchain_height(height, i)


                    
            
    def verify_chain(self, chain):

        first_header = chain[0]
        prev_header = self.read_header(first_header.get('block_height') -1)
        
        for header in chain:

            height = header.get('block_height')

            prev_hash = self.hash_header(prev_header)
            #bits, target = self.get_target(height/2016, chain)
            bits, target = self.KimotoGravityWell(height, chain)            
            _hash = self.pow_hash_header(header)
			
			
            print_msg("prev_hash", prev_hash)
            print_msg("prev_block_hash", header.get('prev_block_hash'))
            print_msg("bits", bits)
            print_msg("bits.header", header.get('bits'))

            try:
                assert prev_hash == header.get('prev_block_hash')
                assert bits == header.get('bits')
                assert int('0x'+_hash,16) < target
            except Exception:
                return False

            prev_header = header

        return True



    def verify_chunk(self, height, index,  hexdata):
        data = hexdata.decode('hex')
        #height = index*2016
        num = len(data)/80

        if index == 0:  
            previous_hash = ("0"*64)
        else:
            prev_header = self.read_header(height-1)
            if prev_header is None: raise
            previous_hash = self.hash_header(prev_header)
       
        bits, target = self.KimotoGravityWell(height)
       
        for i in range(num):
            #height = index*2016 + i
            height = height + i
            raw_header = data[i*80:(i+1)*80]
            header = self.header_from_string(raw_header)
            _hash = self.pow_hash_header(header)
            			
           # print_msg("bits", bits , "(", hex(bits),")")
           # print_msg("bits.header",  header.get('bits') , "(", hex(header.get('bits')),")")
           # print_msg("previous_hash == header.get('prev_block_hash')", (previous_hash == header.get('prev_block_hash')))
            if (bits != header.get('bits')):
              print_msg("previous_hash == header.get('prev_block_hash')", (previous_hash == header.get('prev_block_hash')))
              print_msg("header=",header)
              print_msg("bits", bits , "(", hex(bits),")")          
              print_msg("height=",height,"bits == header.get('bits')", bits == header.get('bits'))
              print_msg("bits.header",  header.get('bits') , "(", hex(header.get('bits')),")")
              print_msg("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
            assert previous_hash == header.get('prev_block_hash')
            assert bits == header.get('bits')
            assert int('0x'+_hash,16) < target

            previous_header = header
            previous_hash = self.hash_header(header)

        self.save_chunk(index, data)
        print_msg("validated chunk %d"%height)

        

    def header_to_string(self, res):
        s = int_to_hex(res.get('version'),4) \
            + rev_hex(res.get('prev_block_hash')) \
            + rev_hex(res.get('merkle_root')) \
            + int_to_hex(int(res.get('timestamp')),4) \
            + int_to_hex(int(res.get('bits')),4) \
            + int_to_hex(int(res.get('nonce')),4)
        return s


    def header_from_string(self, s):
        hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
        h = {}
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hex_to_int(s[76:80])
        return h

    def hash_header(self, header):
        return rev_hex(Hash(self.header_to_string(header).decode('hex')).encode('hex'))

    def pow_hash_header(self, header):
        return rev_hex(getPoWHash(self.header_to_string(header).decode('hex')).encode('hex'))

    def path(self):
        return os.path.join( self.config.path, 'blockchain_headers')

    def init_headers_file(self):
        print_msg("init_headers_file");
        filename = self.path()
        if os.path.exists(filename):
            return
        
        try:
            import urllib, socket
            socket.setdefaulttimeout(30)
            print_msg("downloading ", self.headers_url )
            urllib.urlretrieve(self.headers_url, filename)
            print_msg("done.")
        except Exception:
            print_msg( "download failed. creating file", filename )
            open(filename,'wb+').close()

    def save_chunk(self, index, chunk):
        print_msg("save_chunk");
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(index*2016*80)
        h = f.write(chunk)
        f.close()
        self.set_local_height()

    def save_header(self, header):
        print_msg("save_header");
        data = self.header_to_string(header).decode('hex')
        assert len(data) == 80
        height = header.get('block_height')
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(height*80)
        h = f.write(data)
        f.close()
        self.set_local_height()


    def set_local_height(self):
        name = self.path()
        if os.path.exists(name):
            h = os.path.getsize(name)/80 - 1
            if self.local_height != h:
                self.local_height = h


    def read_header(self, block_height):
        name = self.path()
        if os.path.exists(name):
            f = open(name,'rb')
            f.seek(block_height*80)
            h = f.read(80)
            f.close()
            if len(h) == 80:
                h = self.header_from_string(h)
                return h 

				
    def convbignum(self, bits):
        # convert to bignum
        return  (bits & 0xffffff) *(1<<( 8 * ((bits>>24) - 3)))

    def convbits(self, target):
        # convert it to bits
        MM = 256*256*256
        c = ("%064X"%target)[2:]
        i = 31
        while c[0:2]=="00":
            c = c[2:]
            i -= 1

        c = int('0x'+c[0:6],16)
        if c >= 0x800000:
            c /= 256
            i += 1

        return c + MM * i				
				

    def KimotoGravityWell(self, height, chain=[],data=None):	
	  print_msg ("height=",height,"chain=", chain, "data=", data)
	  BlocksTargetSpacing			= 1 * 60; # 1 minute
	  TimeDaySeconds				= 60 * 60 * 24;
	  PastSecondsMin				= TimeDaySeconds * 0.01;
	  PastSecondsMax				= TimeDaySeconds * 0.14;
	  PastBlocksMin				    = PastSecondsMin / BlocksTargetSpacing;
	  PastBlocksMax				    = PastSecondsMax / BlocksTargetSpacing;

	  
	  BlockReadingIndex             = height - 1
	  BlockLastSolvedIndex          = height - 1
	  TargetBlocksSpacingSeconds    = BlocksTargetSpacing
	  PastRateAdjustmentRatio       = 1.0
	  bnProofOfWorkLimit = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
	  
	
	  
	  if (BlockLastSolvedIndex<=0 or BlockLastSolvedIndex<PastSecondsMin):
		new_target = bnProofOfWorkLimit
		new_bits = self.convbits(new_target)      
		return new_bits, new_target

	  
	  
	  try:
		last = self.read_header(BlockLastSolvedIndex)
		print_msg("read from local")
	  except Exception:
		print_msg("read from chain")
		for h in chain:
		  if h.get('block_height') == BlockLastSolvedIndex:
			print_msg("get block from chain")
			last = h
			break;
	  if (last==None):
		  for h in chain:
			if h.get('block_height') == BlockReadingIndex:
			  #print_msg("get block from chain")
			  last = h
			  break;  
            
            
	  for i in xrange(1,int(PastBlocksMax)+1):
		PastBlocksMass=i
		
		try:
		  reading = self.read_header(BlockReadingIndex)
		  #print_msg("read from local")
		except Exception:
		  #print_msg("read from chain")
		  for h in chain:
			if h.get('block_height') == BlockReadingIndex:
			  #print_msg("get block from chain")
			  reading = h
			  break;
        
		if (reading==None):
		  for h in chain:
			if h.get('block_height') == BlockReadingIndex:
			  #print_msg("get block from chain")
			  reading = h
			  break;        
        
        
        
		if (reading==None or last == None):
		  print_msg("error:reading==None or last == None ",reading,last);
		  return 0x1e0ffff0, 0x00000FFFF0000000000000000000000000000000000000000000000000000000
        
		#print_msg ("last=",last)		
		if (i == 1):
		  print_msg ("reading=",reading)
		  PastDifficultyAverage=self.convbignum(reading.get('bits'))
		else:
		  PastDifficultyAverage= float((self.convbignum(reading.get('bits')) - PastDifficultyAveragePrev) / float(i)) + PastDifficultyAveragePrev;
          
        
 
          
		PastDifficultyAveragePrev = PastDifficultyAverage;
		
		PastRateActualSeconds   = last.get('timestamp') - reading.get('timestamp');
		PastRateTargetSeconds   = TargetBlocksSpacingSeconds * PastBlocksMass;
		PastRateAdjustmentRatio       = 1.0
		if (PastRateActualSeconds < 0):
		  PastRateActualSeconds = 0.0
		
		if (PastRateActualSeconds != 0 and PastRateTargetSeconds != 0):
		  PastRateAdjustmentRatio			= float(PastRateTargetSeconds) / float(PastRateActualSeconds)
		
		EventHorizonDeviation       = 1 + (0.7084 * pow(float(PastBlocksMass)/28.2, -1.228))
		EventHorizonDeviationFast   = EventHorizonDeviation
		EventHorizonDeviationSlow		= float(1) / float(EventHorizonDeviation)
		
		#print_msg ("EventHorizonDeviation=",EventHorizonDeviation,"EventHorizonDeviationFast=",EventHorizonDeviationFast,"EventHorizonDeviationSlow=",EventHorizonDeviationSlow ) 
		
		if (PastBlocksMass >= PastBlocksMin):
		
		  if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) or (PastRateAdjustmentRatio >= EventHorizonDeviationFast)):
			print_msg ("blockreading done PastBlocksMass=",PastBlocksMass)
			break;
			 
		  if (BlockReadingIndex<1):
			print_msg ("blockreading=0 PastBlocksMass=",PastBlocksMass )
			break
		
		   
		  
		   
			
		  
		
		BlockReadingIndex = BlockReadingIndex -1;
		#print_msg ("BlockReadingIndex=",BlockReadingIndex )
		
		
	  print_msg ("for end: PastBlocksMass=",PastBlocksMass ) 
	  bnNew   = PastDifficultyAverage
	  if (PastRateActualSeconds != 0 and PastRateTargetSeconds != 0):
		bnNew *= float(PastRateActualSeconds);
		bnNew /= float(PastRateTargetSeconds);
		
	  if (bnNew > bnProofOfWorkLimit):
		bnNew = bnProofOfWorkLimit

	  # new target
	  new_target = bnNew
	  new_bits = self.convbits(new_target)

	  #print_msg("bits", new_bits , "(", hex(new_bits),")")
	  print_msg ("PastRateAdjustmentRatio=",PastRateAdjustmentRatio,"EventHorizonDeviationSlow",EventHorizonDeviationSlow,"PastSecondsMin=",PastSecondsMin,"PastSecondsMax=",PastSecondsMax,"PastBlocksMin=",PastBlocksMin,"PastBlocksMax=",PastBlocksMax)    
	  


  
	  return new_bits, new_target

    def get_target(self, index, chain=[],data=None):
	  return self.KimotoGravityWell(index*2016,chain,data)
		  
    def get_target_old(self, index, chain=[],data=None):
			max_target = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
			if index == 0: return 0x1e0ffff0, 0x00000FFFF0000000000000000000000000000000000000000000000000000000
			global Kimoto_vals
			k_vals = Kimoto_vals

			KGW = False
			global KGW_headers
			if index >= 6000:
				KGW = True

			minKGWblocks = 15
			maxKGWblocks = 201


			if KGW and data or chain:
				m= index % 201
				if chain:
					m = 0

				try:
					if m > 0:
						raw_l_header = data[(m-1)*80:(m)*80]
						last = self.header_from_string(raw_l_header)
						print_msg("last=", last)
						ts = last.get('timestamp')
						t = self.convbignum(last.get('bits'))
						KGW_headers[(index-1)%201] = {'header':last,'t':t, 'ts':ts}
					else:
						last = self.read_header(index-1)
						print_msg("last=", last )
						t = self.convbignum(last.get('bits'))
						print_msg(" t = self.convbignum(last.get('bits'))=", t )					
						ts = last.get('timestamp')
						KGW_headers[(index-1)%201] = {'header':last,'t':t, 'ts':ts}
				except Exception:
					for h in chain:
						if h.get('block_height') == index-1:
							last = h
							ts = last.get('timestamp')
							t = self.convbignum(last.get('bits'))
							KGW_headers[(index-1)%201] = {'header':last,'t':t,'ts':ts}

				for i in xrange(1,maxKGWblocks+1):
					blockMass = i
					KGW_i = index%201 - i
					if KGW_i < 0:
						KGW_i = 201 + KGW_i
					if 'header' not in KGW_headers[KGW_i] and blockMass != 1:
						if (m-i) >= 0:
							raw_f_header = data[(m-i)*80:(m-i+1)*80]
							first = self.header_from_string(raw_f_header)
						else:
							first = self.read_header(index-i)
						t = self.convbignum(first.get('bits'))
						ts = first.get('timestamp')
						KGW_headers[KGW_i] = {'header':first,'t':t, 'ts':ts}
					first = KGW_headers[KGW_i]

					if blockMass == 1:
						print first
						pastDiffAvg = first['t']
					else:
						pastDiffAvg = (first['t'] - pastDiffAvgPrev)/Decimal(blockMass) + pastDiffAvgPrev
					pastDiffAvgPrev = pastDiffAvg

					if blockMass >= minKGWblocks:
						pastTimeActual = KGW_headers[(index-1)%201]['ts'] - first['ts']
						pastTimeTarget = 15*blockMass
						if pastTimeActual < 0:
							pastTimeActual = 0
						pastRateAdjRatio = 1.0
						if pastTimeActual != 0 and pastTimeTarget != 0:
							pastRateAdjRatio = Decimal(pastTimeTarget)/Decimal(pastTimeActual)
						eventHorizon = k_vals[(blockMass-1)]
						eventHorizonFast = eventHorizon
						eventHorizonSlow = 1/Decimal(eventHorizon)
						if pastRateAdjRatio <= eventHorizonSlow or pastRateAdjRatio >= eventHorizonFast:
							print_msg('blockMass: ', blockMass, 'adjratio: ', pastRateAdjRatio, ' eventHorizon: ', eventHorizon)
							first = first['header']
							break
						elif blockMass == maxKGWblocks:
							print_msg('blockMass: ', blockMass, 'adjratio: ', pastRateAdjRatio, ' eventHorizon: ', eventHorizon)
							first = first['header']

			else:
				# Vertcoin: go back the full period unless it's the first retarget
				if index == 1:
					first = self.read_header(0)
				else:
					first = self.read_header((index-1)*201-1)
				last = self.read_header(index*201-1)
				if last is None:
					for h in chain:
						if h.get('block_height') == index*201-1:
							last = h


			nActualTimespan = pastTimeActual
			nTargetTimespan = pastTimeTarget
			target = pastDiffAvg

			# new target
			new_target = min( max_target, (target * nActualTimespan)/nTargetTimespan )

			new_bits = self.convbits(new_target)

			return new_bits, new_target
				
				
				
    def request_header(self, i, h, queue):
        print_msg("requesting header %d from %s"%(h, i.server))
        i.send([ ('blockchain.block.get_header',[h])], lambda i,r: queue.put((i,r)))

    def retrieve_header(self, i, queue):
        while True:
            try:
                ir = queue.get(timeout=1)
            except Queue.Empty:
                print_msg('timeout')
                continue

            if not ir: 
                continue

            i, r = ir

            if r.get('error'):
                print_msg('Verifier received an error:', r)
                continue

            # 3. handle response
            method = r['method']
            params = r['params']
            result = r['result']

            if method == 'blockchain.block.get_header':
                return result
                


    def get_chain(self, interface, final_header):

        header = final_header
        chain = [ final_header ]
        requested_header = False
        queue = Queue.Queue()

        while self.is_running():

            if requested_header:
                header = self.retrieve_header(interface, queue)
                if not header: return
                chain = [ header ] + chain
                requested_header = False

            height = header.get('block_height')
            previous_header = self.read_header(height -1)
            if not previous_header:
                self.request_header(interface, height - 1, queue)
                requested_header = True
                continue

            # verify that it connects to my chain
            prev_hash = self.hash_header(previous_header)
            if prev_hash != header.get('prev_block_hash'):
                print_msg("reorg")
                self.request_header(interface, height - 1, queue)
                requested_header = True
                continue

            else:
                # the chain is complete
                return chain


    def get_and_verify_chunks(self, i, header, height):

        queue = Queue.Queue()
        min_index = (self.local_height + 1)/2016
        max_index = (height + 1)/2016
        n = min_index
        while n < max_index + 1:
            print_msg( "Requesting chunk :", n )
            r = i.synchronous_get([ ('blockchain.block.get_chunk',[n])])[0]
            #print_msg('blockchain.block.get_chunk=',r)
            if not r: 
                continue
            try:
                self.verify_chunk(height+n,n, r)
                n = n + 1
            except Exception:
                print_msg('Verify chunk failed!',  sys.exc_info()[0])
                n = n - 1
                if n < 0:
                    return False

        return True

