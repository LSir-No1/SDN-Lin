#!/usr/bin/env python

import socket
import cv2
import numpy

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
address_server = ('', 8010)
sock.connect(address_server)


capture = cv2.VideoCapture("/home/longmao/snow.mp4")
ret, frame = capture.read()         #bool & 3D array
encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 50]   #encode
try:
 while ret:     # if True
    img_encode = cv2.imencode('.jpg', frame, encode_param)[1]
    data = numpy.array(img_encode)
    stringData = data.tostring()        
    sock.send(str(len(stringData)).ljust(16))    # send the length
    sock.send(stringData)                        # send the message of image
    ret, frame = capture.read()
    cv2.resize(frame, (640, 480))
except :
    pass

sock.close()
cv2.destroyAllWindows()

