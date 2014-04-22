import pyopencl as cl
import numpy as np
import time
import crypt
import sys
ctx = cl.create_some_context()
queue = cl.CommandQueue(ctx)
program = cl.Program(ctx,open("md5.cl","r").read()).build()
mf = cl.mem_flags

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]
def testPasswords(in_s,salt,expected):

  s = ""
  indexes = [0]*len(in_s)
  sizes = [0]*len(in_s)
  slist = [0]*len(in_s)
  l = 0
  for i in range(0,len(in_s)):
    indexes[i] = l
    slist[i] = in_s[i]
    sizes[i] = len(in_s[i])
    
    l += len(in_s[i])
  
  s = "".join(slist)
  start = time.time()
  s_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=s )
  salt_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=salt)
  corrhash_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=expected)
  indexes_arr = np.array(indexes,dtype=np.uint32)
  indexes_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=indexes_arr )
  sizes_arr = np.array(sizes,dtype=np.uint32)
  sizes_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=sizes_arr )
  
  
  corr_array = np.zeros(64,dtype=np.uint8)
  corr_buf = cl.Buffer(ctx, mf.WRITE_ONLY, corr_array.nbytes)

  corr2a = np.zeros(1,dtype=np.uint32)
  corr2a_buf = cl.Buffer(ctx, mf.WRITE_ONLY, corr2a.nbytes)
  #print "Start kernel"
  program.computeHashes(queue,indexes_arr.shape,None,s_buf,indexes_buf,sizes_buf,salt_buf,corrhash_buf,corr_buf,corr2a_buf)
  cl.enqueue_copy(queue,corr_array,corr_buf).wait()
  cl.enqueue_copy(queue,corr2a,corr2a_buf).wait()
  #print "End"
  end = time.time()
  #print end-start
  password = "".join(map(chr,list(corr_array)))
  #print corr2a
  corr_buf.release()
  s_buf.release()
  salt_buf.release()
  corrhash_buf.release()
  indexes_buf.release()
  sizes_buf.release()
  corr2a_buf.release()
  #print password.split("\x00")[0]
  #print in_s[index]
  if crypt.crypt(password.split("\x00")[0],expected.strip("\x00")) == expected.strip("\x00"):
    return password.split("\x00")[0]
  return None
 

i = ["abcdef\x00"]*100000;


wordlist_chunk = []
salt = sys.argv[1].split("$")[2]
print salt
f = open(sys.argv[2],"r")
tested = 0
l = f.readline()
while l != "":
    wordlist_chunk.append(l.strip("\r\n\t ")+"\x00")
    if len(wordlist_chunk) >= 100000:
        res = testPasswords(wordlist_chunk,salt+"\x00",sys.argv[1]+"\x00")
        if res != None:
            print "Cracked, Password is:",res
            exit(0)
        wordlist_chunk = []
        tested += 100000
        print "%d Passwords tested"%tested
    l = f.readline()
res = testPasswords(wordlist_chunk,salt+"\x00",sys.argv[1]+"\x00")
if res != None:
    print "Cracked, Password is:",res
    exit(0)
