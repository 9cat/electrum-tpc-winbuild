#!/usr/bin/env python

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


	
def convbignum(bits):
        # convert to bignum
        return  (bits & 0xffffff) *(1<<( 8 * ((bits>>24) - 3)))

def convbits(target):
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
def header_from_string(s):
        hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
        h = {}
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hex_to_int(s[76:80])
        return h	
        
def read_header(block_height):
        name = '/home/temple/.electrum-tpc/blockchain_headers'
        if os.path.exists(name):
            f = open(name,'rb')
            f.seek(block_height*80)
            h = f.read(80)
            f.close()
            if len(h) == 80:
                h = header_from_string(h)
                return h 
        
        
def get_target(index, chain=[],data=None):
      

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

        #print ("Kimoto_vals=",Kimoto_vals);
		
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
                    last = read_header(index-1)
                    #last = header_from_string("{'nonce': 1060557, 'prev_block_hash': '0474ff4ea984f35e5962d926d1b6df78b2462df8c140b111d3d2c7a722ed777f', 'timestamp': 1399003224, 'merkle_root': '020c6a72792df48b8d89e607446c51a591e579c750a63d79892db46b4fe18cf5', 'version': 2, 'bits': 504365040}")
                    
                    print_msg("last.get('bits')=", last.get('bits') )
                    t = convbignum(last.get('bits'))
                    #print_msg(" t = self.convbignum(last.get('bits'))=", t )					
                    ts = last.get('timestamp')
                    KGW_headers[(index-1)%201] = {'header':last,'t':t, 'ts':ts}
                    #print ("KGW_headers=",KGW_headers[(index-1)%201])
            except Exception:
                for h in chain:
                    if h.get('block_height') == index-1:
                        last = h
                        ts = last.get('timestamp')
                        t = self.convbignum(last.get('bits'))
                        KGW_headers[(index-1)%201] = {'header':last,'t':t,'ts':ts}
            #print ("KGW_headers=",KGW_headers)
            #return
            for i in xrange(1,maxKGWblocks+1):
                blockMass = i
                KGW_i = index%201 - i
                if KGW_i < 0:
                    KGW_i = 201 + KGW_i
                if 'header' not in KGW_headers[KGW_i] and blockMass != 1:
                    if (m-i) >= 0:
                        raw_f_header = data[(m-i)*80:(m-i+1)*80]
                        first = header_from_string(raw_f_header)
                    else:
                        first = read_header(index-i)
                    t = convbignum(first.get('bits'))
                    ts = first.get('timestamp')
                    KGW_headers[KGW_i] = {'header':first,'t':t, 'ts':ts}
                first = KGW_headers[KGW_i]
                #print ("first=",first);
                if blockMass == 1:
                    pastDiffAvg = first['t']
                else:
                    pastDiffAvg = (first['t'] - pastDiffAvgPrev)/float(blockMass) + pastDiffAvgPrev
                pastDiffAvgPrev = pastDiffAvg

                if blockMass >= minKGWblocks:
                    pastTimeActual = KGW_headers[(index-1)%201]['ts'] - first['ts']
                    pastTimeTarget = 15*blockMass
                    if pastTimeActual < 0:
                        pastTimeActual = 0
                    pastRateAdjRatio = 1.0
                    if pastTimeActual != 0 and pastTimeTarget != 0:
                        pastRateAdjRatio = float(pastTimeTarget)/float(pastTimeActual)
                    eventHorizon = k_vals[(blockMass-1)]
                    eventHorizonFast = eventHorizon
                    eventHorizonSlow = 1/float(eventHorizon)
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

        new_bits = convbits(new_target)

        return new_bits, new_target

def KimotoGravityWell(index, chain=[],data=None):
  BlocksTargetSpacing			= 1 * 60; # 1 minute
  TimeDaySeconds				= 60 * 60 * 24;
  PastSecondsMin				= TimeDaySeconds * 0.01;
  PastSecondsMax				= TimeDaySeconds * 0.14;
  PastBlocksMin				    = PastSecondsMin / BlocksTargetSpacing;
  PastBlocksMax				    = PastSecondsMax / BlocksTargetSpacing;

  
  BlockReadingIndex             = index - 1
  BlockLastSolvedIndex          = index - 1
  TargetBlocksSpacingSeconds    = BlocksTargetSpacing
  PastRateAdjustmentRatio       = 1.0
  bnProofOfWorkLimit = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  
  
  
  if (BlockLastSolvedIndex<=0 or BlockLastSolvedIndex<PastSecondsMin):
    new_target = bnProofOfWorkLimit
    new_bits = convbits(new_target)      
    return new_bits, new_target

  
  
  try:
    last = read_header(BlockLastSolvedIndex)
  except Exception:
    for h in chain:
      if h.get('block_height') == BlockLastSolvedIndex:
        last = read_header(BlockLastSolvedIndex)
        break;

  for i in xrange(1,int(PastBlocksMax)+1):
    PastBlocksMass=i
	
    try:
      reading = read_header(BlockReadingIndex)
    except Exception:
      for h in chain:
        if h.get('block_height') == BlockReadingIndex:
          reading = read_header(BlockReadingIndex)
          break;
	
	
    if (i == 1):
      PastDifficultyAverage=convbignum(reading.get('bits'))
    else:
      PastDifficultyAverage= float((convbignum(reading.get('bits')) - PastDifficultyAveragePrev) / float(i)) + PastDifficultyAveragePrev;
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

  print_msg ("PastRateAdjustmentRatio=",PastRateAdjustmentRatio,"EventHorizonDeviationSlow",EventHorizonDeviationSlow,"PastSecondsMin=",PastSecondsMin,"PastSecondsMax=",PastSecondsMax,"PastBlocksMin=",PastBlocksMin,"PastBlocksMax=",PastBlocksMax)    
  # new target
  new_target = bnNew
  new_bits = convbits(new_target)      
  return new_bits, new_target
      
        
        
chain = [{u'nonce': 3113028288, u'prev_block_hash': u'29f7b686dce9782c287aa8dd3df3fae7fb2d5a346f6af3c5ba877c5554ecf01b', u'timestamp': 1410629659, u'merkle_root': u'4ed5f337786ff1a86e5011e592dc50140887465ccf4bf6f3c1332e55986cf4af', u'block_height': 94907, u'version': 2, u'bits': 503785119}, {u'nonce': 28836352, u'prev_block_hash': u'5b8b7dc53579ddecb3246f0de3be646ea38c0e94fd27b7523228ca6aade4b98f', u'timestamp': 1410629738, u'merkle_root': u'6fcca3b3ab3abc5e65f277d67b56303a7a67d3059d67b37334205b0a426dc669', u'block_height': 94908, u'version': 2, u'bits': 503785079}, {u'nonce': 2620915968, u'prev_block_hash': u'42edc8facd095f49c7be36151591aa6fc02ce9959d4d3b832140047498f57735', u'timestamp': 1410629782, u'merkle_root': u'da088cf38cbaf55a474450ba7676d5a25e0d40ad31f726e5049cbb0ad94cb74b', u'block_height': 94909, u'utxo_root': u'2704ac6cb82bbbe898c626eda2acb6f7b996bd5a645abaad5f1afd8e404e20a6', u'version': 2, u'bits': 503784608}]
        
        
        
height = 92736
bits, target  = KimotoGravityWell(height) 
h = read_header(height)
print_msg("string=",h)
print_msg("bits", bits , "(", hex(bits),")")
print_msg("bits.header",  h.get('bits') , "(", hex(h.get('bits')),")")
print_msg("***********************************************************")        

sys.exit()

for h in chain:
  #height = h.get('block_height')
  #print_msg("height ", height )
  #bits, target  = get_target(height/201, chain)  
  #print_msg("bits", bits)
  #print_msg("bits.header",  h.get('bits'))
  #print_msg("-------------")
  bits, target  = KimotoGravityWell(height, chain) 
  print_msg("bits", bits , "(", hex(bits),")")
  print_msg("bits.header",  h.get('bits') , "(", hex(h.get('bits')),")")
  print_msg("***********************************************************")
  
  
  
  
  