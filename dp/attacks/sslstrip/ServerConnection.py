# Copyright (c) 2004-2009 Moxie Marlinspike
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import logging, re, string, random, zlib, gzip
# CHANGE: BytesIO from io, also instead of StringIO
from io import BytesIO

from twisted.web.http import HTTPClient
# CHANGE: Relative imports
from .URLMonitor import URLMonitor

class ServerConnection(HTTPClient):

    ''' The server connection is where we do the bulk of the stripping.  Everything that
    comes back is examined.  The headers we dont like are removed, and the links are stripped
    from HTTPS to HTTP.
    '''

    urlExpression     = re.compile(r"(https://[\w\d:#@%/;$()~_?\+-=\\\.&]*)", re.IGNORECASE)
    urlType           = re.compile(r"https://", re.IGNORECASE)
    urlExplicitPort   = re.compile(r'https://([a-zA-Z0-9.]+):[0-9]+/',  re.IGNORECASE)

    def __init__(self, command, uri, postData, headers, client):
        self.command          = command
        # CHANGE: decode
        self.decoded_command  = command.decode('utf-8')
        self.uri              = uri
        self.postData         = postData
        self.headers          = headers
        self.client           = client
        self.urlMonitor       = URLMonitor.getInstance()
        self.isImageRequest   = False
        self.isCompressed     = False
        self.contentLength    = None
        self.shutdownComplete = False

    def getLogLevel(self):
        return logging.DEBUG

    def getPostPrefix(self):
        return "POST"

    def sendRequest(self):
        # CHANGE: decode
        encoded_uri = self.uri.encode('utf-8')

        logging.log(self.getLogLevel(), "Sending Request: %s %s"  % (self.decoded_command, self.uri))
        self.sendCommand(self.command, encoded_uri)

    def sendHeaders(self):
        for header, value in self.headers.items():
            logging.log(self.getLogLevel(), "Sending header: %s : %s" % (header, value))
            
            # CHANGE: decode
            encoded_header = header.encode('utf-8')
            encoded_value = value.encode('utf-8')
            self.sendHeader(encoded_header, encoded_value)

        self.endHeaders()

    def sendPostData(self):
        # CHANGE: decode
        decoded_postData = self.postData.decode('utf-8')

        logging.warning(self.getPostPrefix() + " Data (" + self.headers['host'] + "):\n" + str(decoded_postData))
        self.transport.write(self.postData)

    def connectionMade(self):
        logging.log(self.getLogLevel(), "HTTP connection made.")
        self.sendRequest()
        self.sendHeaders()
        
        # CHANGE: decoded
        if (self.decoded_command == 'POST'):
            self.sendPostData()

    def handleStatus(self, version, code, message):
        logging.log(self.getLogLevel(), "Got server response: %s %s %s" % (version, code, message))
        self.client.setResponseCode(int(code), message)

    def handleHeader(self, key, value):
        # CHANGE: decoded key and value
        decoded_key = key.decode('utf-8')
        decoded_value = value.decode('utf-8')

        logging.log(self.getLogLevel(), "Got server header: %s:%s" % (decoded_key, value))

        if (decoded_key.lower() == 'location'):
            value = self.replaceSecureLinks(decoded_value)

        if (decoded_key.lower() == 'content-type'):
            if (decoded_value.find('image') != -1):
                self.isImageRequest = True
                logging.debug("Response is image content, not scanning...")

        if (decoded_key.lower() == 'content-encoding'):
            if (decoded_value.find('gzip') != -1):
                logging.debug("Response is compressed...")
                self.isCompressed = True
        elif (decoded_key.lower() == 'content-length'):
            self.contentLength = value
        elif (decoded_key.lower() == 'set-cookie'):
            self.client.responseHeaders.addRawHeader(key, value)
        else:
            self.client.setHeader(key, value)

    def handleEndHeaders(self):
       if (self.isImageRequest and self.contentLength != None):
           self.client.setHeader("Content-Length", self.contentLength)

       if self.length == 0:
           self.shutdown()
                        
    def handleResponsePart(self, data):
        if (self.isImageRequest):
            self.client.write(data)
        else:
            HTTPClient.handleResponsePart(self, data)

    def handleResponseEnd(self):
        if (self.isImageRequest):
            self.shutdown()
        else:
            HTTPClient.handleResponseEnd(self)

    def handleResponse(self, data):
        if (self.isCompressed):
            logging.debug("Decompressing content...")
            # CHANGE: BytesIO
            data = gzip.GzipFile('', 'rb', 9, BytesIO(data)).read()
        
        # CHANGE: Decoded
        decoded_data = data.decode('utf-8')
        
        logging.log(self.getLogLevel(), "Read from server:")
        logging.log(self.getLogLevel(), decoded_data)

        # CHANGE: Try and except changing and re encoding
        try: 
            data = self.replaceSecureLinks(decoded_data).encode('utf-8')
        except:
            pass

        if (self.contentLength != None):
            # CHANGE: changed int to string
            self.client.setHeader('Content-Length', str(len(data)))
        
        # CHANGE: Try and except, it aint pretty but it resolves the issue
        try:
            self.client.write(data)
            self.shutdown()
        except:
            pass

    def replaceSecureLinks(self, data):
        iterator = re.finditer(ServerConnection.urlExpression, data)

        for match in iterator:
            url = match.group()

            logging.debug("Found secure reference: " + url)

            url = url.replace('https://', 'http://', 1)
            url = url.replace('&amp;', '&')
            self.urlMonitor.addSecureLink(self.client.getClientIP(), url)

        data = re.sub(ServerConnection.urlExplicitPort, r'http://\1/', data)
        return re.sub(ServerConnection.urlType, 'http://', data)

    def shutdown(self):
        if not self.shutdownComplete:
            self.shutdownComplete = True
            self.client.finish()
            self.transport.loseConnection()


