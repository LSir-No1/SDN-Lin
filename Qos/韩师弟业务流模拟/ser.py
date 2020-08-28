#!/usr/bin/env python

import socket
import cv2
import numpy

# the size of image
def recv_size(sock, count):
     buf = ''
     while count:
         newbuf = sock.recv(count)
         if not newbuf: return None
         buf += newbuf
         count -= len(newbuf)
     return buf

# socket:
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
address = ('', 8010)                #HOST: ANY;  PORT:8010
s.bind(address)
s.listen(True)
print ('Waiting for images...')


try:
    # if connect, return TCPconn. transport by conn
 conn, addr = s.accept()

 while True:
     # get the size
     length = recv_size(conn, 16)
     if isinstance(length, str):         # is the type string?
         stringData = recv_size(conn, int(length))    # get the message of image by the length
         # if the size is OK, get other messages of the image
         data =numpy.fromstring(stringData, dtype='uint8')    # 1D array
         decimg = cv2.imdecode(data, 1)   #Decoded image   mat
         cv2.imshow('SNOW', decimg)    #Show the image
         if cv2.waitKey(10) == 27:       #Esc
             break
         print('Image recieved successfully!')
     if cv2.waitKey(10) == 27:           #Esc
         break
except:
    pass

s.close()
cv2.destroyAllWindows()





