#!/usr/bin/python3
# Import testssl.sh CSV to ELasticSearch
 
from elasticsearch_dsl import Document, Object, Date, Keyword, Integer, Short, Boolean
from datetime import datetime
from tzlocal import get_localzone
import csv
import re
import pprint     # for debugging purposes only
import ipaddress
import socket

pp = pprint.PrettyPrinter(indent=4)

tz = get_localzone()
reDefaultFilename = re.compile("(?:^|/)(?P<ip>\d+\.\d+\.\d+\.\d+)(:(?P<port>\d+))?-(?P<datetime>\d{8}-\d{4})\.csv$")
reDefaultHostFilename = re.compile("(?:^|/)(?P<hostname>[a-zA-Z.]+)(_p(?P<port>\d+))?-(?P<datetime>\d{8}-\d{4})\.csv$")
reProtocol = re.compile("^(?:SSLv\\d|TLS\\d(?:_\\d)?)$")
reCipherTests = re.compile("^cipherlist_(.*)$")
reIpHostColumn = re.compile("^(.*)/(.*)$")
reCipherColumnName = re.compile("^cipher_x")
reCipherDetails = re.compile("^\\S+\\s+(\\S+)")
reCipherTests = re.compile("^cipherlist_(.*)$")
reDefaultProtocol = re.compile("^Default protocol (\\S+)")
reDefaultCipher = re.compile("^(.*),")
reKeySize = re.compile("\\S+ (\\d+) bits")
reSignAlgorithm = re.compile("(\\S+)")
reCertFingerprintColumnName = re.compile('^cert_fingerprint')
reFPMD5 = re.compile("MD5 (\\S+)")
reFPSHA1 = re.compile("SHA1 (\\S+)")
reFPSHA256 = re.compile("SHA256 (\\S+)")
reCN = re.compile("^(.*?)[\\s\\(]")
reSAN = re.compile(": (.*)$")
reIssuer = re.compile("'issuer= (.*?)' \\(")
reExpiration = re.compile("--> (.*)\\)")
reOCSPURI = re.compile(" : (?!--)(.*)")
reGradeCapReason = re.compile("^grade_cap_reason_")
reCipherTLS = re.compile("^cipher-tls")

reOffers = re.compile("(?<!not )offered")
reNotOffered = re.compile("not offered")
rePassed = re.compile("passed")
reSelfSigned = re.compile("self signed")
reOk = re.compile("\\(OK\\)")
reYes = re.compile("yes", re.IGNORECASE)
#reVulnerable = re.compile("\\(NOT ok\\)", re.IGNORECASE)
reVulnerable = re.compile("not vulnerable", re.IGNORECASE)

errors = {
"SSLv2":"Obsolete protocol: SSLv2",
"SSLv3":"Obsolete protocol: SSLv3",
"TLS1":"Obsolete protocol: TLS1",
"TLS1_1":"Obsolete protocol: TLSV1.1",
"TLS1_2":"Obsolete protocol: TLS1.2",
"TLS1_3":"Obsolete protocol: TLS1.3",
"NPN":"Obsolete protocol: NPN/SPDY",
"ALPN_HTTP2":"Obsolete protocol: ALPN/HTTP2",
"cipherlist_NULL":"Cipher category: Null ciphers (no encryption)",
"cipherlist_aNULL":"Cipher category: Anonymous NULL Ciphers (no authentication)",
"cipherlist_EXPORT":"Cipher category: Export ciphers (w/o ADH+NULL)",
"cipherlist_LOW":"Cipher category: LOW: 64 Bit + DES, RC[2,3] (w/o export)",
"cipherlist_3DES_IDEA":"Cipher category: Tripple DES Ciphers / IDEA",
"cipherlist_AVERAGE":"Cipher category: Obsolete CBC Ciphers (AES, ARIA etc)",
"cipherlist_STRONG":"Cipher category: Strong encrytion (AHEAD ciphers)",
"PFS":"PFS is not offered",
"cipher_order":"No cipher order",
"cert_trust":"Certificate: No trust",
"cert_chain_of_trust":"Certificate: Chain of trust incomplete",
"cert_expirationStatus":"Certificate: Close to expiry/expired",
"DNS_CAArecord":"Server defaults: DNS CAA RR (experimental)",
"certificate_transparency":"Certificate: No transparancy",
"HSTS_time":"Header Response: No HSTS or time too short",
"X-Frame-Options":"Headers: Missing X-Frame-Options",
"X-Content-Type-Options":"Headers: Missing X-Content-Type-Options",
"Content-Security-Policy":"Headers: Missing Content-Security-Policy",
"Referrer-Policy":"Headers: Missing Referrer-Policy",
"X-XSS-Protection":"Headers: Missing X-XSS-Protection",
"heartbleed":"Vulnerability: Heartbleed (CVE-2014-0160): %1",
"CCS":"Vulnerability: CCS (CVE-2014-0224): %1",
"ticketbleed":"Vulnerability: Ticketbleed (CVE-2016-9244) – experimental: %1",
"ROBOT":"Vulnerability: ROBOT: %1",
"secure_renego":"Vulnerability: Secure Renogotiation (RFC 5746): %1",
"secure_client_renego":"Vulnerability: Secure Client-Initiated Renegotiation: %1",
"CRIME_TLS":"Vulnerability: CRIME, TLS (CVE-2012-4929): %1",
"BREACH":"Vulnerability: BREACH (CVE-2013-3587): %1",
"POODLE_SSL":"Vulnerability: POODLE, SSL (CVE-2014-3566): %1",
"fallback_SCSV":"Vulnerability: TLS_FALLBACK_SCSV (RFC 7507): %1",
"SWEET32":"Vulnerability: SWEET32 (CVE-2016-2183, CVE-2016-6329): %1",
"FREAK":"Vulnerability: FREAK (CVE-2015-0204): %1",
"DROWN":"Vulnerability: DROWN (CVE-2016-0800, CVE-2016-0703): %1",
"LOGJAM":"Vulnerability: LOGJAM (CVE-2015-4000), experimental: %1",
"BEAST":"Vulnerability: BEAST (CVE-2011-3389): %1",
"BEAST_CBC_TLS1":"Vulnerability: BEAST Cipher - TLS1 :%1",
"LUCKY13":"Vulnerability: LUCKY13 (CVE-2013-0169), experimental: %1",
"RC4":"Vulnerability: RC4 (CVE-2013-2566, CVE-2015-2808): %1",
"cert_serialNumberLen":"Serial number length: %1",
"HSTS":"HTTP Strict Transport Security (HSTS): %1",
"security_headers":"Security headers: %1",
"cert_notAfter":"Certificate nearly expired",
"cert_revocation":"Certificate revocation: %1"
}

class DocTestSSLResult(Document):
    
    source = Keyword(fields={'raw': Keyword()})
    result = Boolean()
#    '@timestamp' = Date()
    ip = Keyword()
    hostname = Keyword()
    port = Integer()
    rev_dns = Keyword()
    svcid = Keyword()
    internal = Boolean()
    protocols = Keyword(multi=True)
    ksidentifier = Integer()

    ciphers = Keyword(multi=True, fields={'raw': Keyword()})
    ciphertests = Keyword(multi=True)
    serverpref = Object(
            properties = {
                "cipher_order": Boolean(),
                "protocol": Keyword(),
                "cipher": Keyword(fields={'raw': Keyword()})
                })
    cert = Object(
            properties = {
                "keysize": Short(),
                "sign_algo": Keyword(fields={'raw': Keyword()}),
                "md5_fingerprint": Keyword(),
                "sha1_fingerprint": Keyword(),
                "sha256_fingerprint": Keyword(),
                "cn": Keyword(fields={'raw': Keyword()}),
                "san": Keyword(multi=True, fields={'raw': Keyword()}),
                "issuer": Keyword(fields={'raw': Keyword()}),
                "ev": Boolean(),
                "chain_of_trust": Boolean(),
                "self_signed": Boolean(),
                "expiration": Date(),
                "ocsp_uri": Keyword(fields={'raw': Keyword()}),
                "ocsp_stapling": Boolean(),
                })
    issues = Object(
               properties = {
                 "critical": Keyword(multi=True, fields={'raw': Keyword()}),
                 "high": Keyword(multi=True, fields={'raw': Keyword()}),
                 "medium": Keyword(multi=True, fields={'raw': Keyword()}),
                 "low": Keyword(multi=True, fields={'raw': Keyword()}),
             })
    grade = Object(
               properties = {
                 "overall": Keyword(fields={'raw': Keyword()}),
                 "reasons" : Keyword(multi=True, fields={'raw': Keyword()})
               })
    vulnerabilities = Keyword(multi=True)

#    class Index:
#        name = 'ssl'
#        settings = {
#          "number_of_shards": 1,
#        }

    def parseCSVLine(self, line):
        if line['id'] == "id":
            return
        if not self.ip or not self.hostname or not self.port:   # host, ip and port
            m = reIpHostColumn.search(line['fqdn/ip'])
            if m:
                self.hostname, self.ip = m.groups()
            
            # Return if not IP Address is given
            if self.ip == '':
                return
            
            self.port = int(line['port'])
            self.internal = ipaddress.ip_address(self.ip).is_private
            try:
                self.rev_dns = socket.gethostbyaddr(self.ip)[0]
            except:
                print("") 

        if reProtocol.search(line['id']) and reOffers.search(line['finding']):     # protocols
            self.result = True
            m = reProtocol.search(line['id'])
            if m:
                self.protocols.append(line['id'].upper())
        elif line['id'] == 'NPN' and reOffers.search(line['finding']):
             self.protocols.append("NPN/SPDY")
        elif line['id'] == "ALPN_HTTP2" and not reNotOffered.search(line['finding']):
            self.protocols.append(line['id'].replace("_","/"))
        elif reCipherColumnName.search(line['id']):                  # ciphers
            m = reCipherDetails.search(line['finding'])
            if m:
                self.ciphers.append(m.group(1))
        elif reCipherTests.search(line['id']) and reOffers.search(line['finding']):                       # cipher tests
            m = reCipherTests.search(line['id'])
            if m:
                self.ciphertests.append(m.group(1))
        elif line['id'] == "cipher_order":                                 # server prefers cipher
#            self.serverpref.cipher_order = bool(reOk.search(line['finding']))
            self.serverpref.cipher_order = bool(line['severity'] == 'OK')
        elif line['id'] == "protocol_negotiated":                           # preferred protocol
            m = reDefaultProtocol.search(line['finding'])
            if m:
                self.serverpref.protocol = m.group(1)
        elif line['id'] == "cipher_negotiated":                          # preferred cipher
            m = reDefaultCipher.search(line['finding'])
            if m:
                self.serverpref.cipher = m.group(1)
        elif line['id'] == "cert_keySize(?:^|/)(?P<hostname>[a-zA-Z.]+)(_p(?P<port>\d+))?-(?P<datetime>\d{8}-\d{4})\.csv$":                              # certificate key size
            m = reKeySize.search(line['finding'])
            if m:
                self.cert.keysize = int(m.group(1))
        elif line['id'] == "cert_signatureAlgorithm":                             # certificate sign algorithm
            m = reSignAlgorithm.search(line['finding'])
            if m:
                self.cert.sign_algo = m.group(1)
        elif reCertFingerprintColumnName.search(line['id']):		# certificate fingerprints
            if line['id'] == "cert_fingerprintMD5":
                self.cert.md5_fingerprint = line['finding']
            if line['id'] == "cert_fingerprintSHA1":
                self.cert.sha1_fingerprint = line['finding']
            if line['id'] == "cert_fingerprintSHA256":
                self.cert.sha256_fingerprint = line['finding'] 
        elif line['id'] == "cert_commonName":                                    # certificate CN
             self.cert.cn = line['finding']
#            m = reCN.search(line['finding'])
#            if m:
#                self.cert.cn = m.group(1)
        elif line['id'] == "cert_chain_of_trust":
            m = rePassed.search(line['finding'])
            self.cert.chain_of_trust = bool(m != None)
            
            m = reSelfSigned.search(line['finding'])
            self.cert.self_signed = bool(m != None)

        elif line['id'] == "cert_subjectAltName":                                   # certificate SAN
            sans = line['finding']
            if line['finding'] == "No SAN, browsers are complaining":
                self.cert.san.append(line['finding'])
            else:  
              for san in sans.split(" "):
                if san != "--":
                    self.cert.san.append(san)
        elif line['id'] == "issuer":                                # certificate issuer
            m = reIssuer.search(line['finding'])
            if m:
                self.cert.issuer = m.group(1)
        elif line['id'] == "cert_certificatePolicies_EV":                                    # certificate extended validation
            self.cert.ev = bool(reYes.search(line['finding']))
        elif line['id'] == "cert_notAfter":                            # certificate expiration
#            m = reExpiration.search(line['finding'])
#            if m:
                unparsedDate = line['finding']
                self.cert.expiration = datetime.strptime(unparsedDate, "%Y-%m-%d %H:%M")
        elif line['id'] == "cert_ocspURL":                              # certificate OCSP URI
            m = reOCSPURI.search(line['finding'])
            if m:
                self.cert.ocsp_uri = m.group(1)
            else:
                self.cert.ocsp_uri = "-"
        elif line['id'] == "OCSP_stapling":                         # certificate OCSP stapling
            self.cert.ocsp_stapling = not bool(reNotOffered.search(line['finding']))
        elif line['id'] in ("heartbleed", "CCS", "ticketbleed", "ROBOT", "secure_renego", "sec_client_renego", "CRIME_TLS", "BREACH", "POODLE_SSL", "fallback_SCSV", "SWEET32", "FREAK", "DROWN", "LOGJAM", "BEAST", "LUCKY13", "RC4"):
            if line['severity'] != 'OK' and line['severity'] != 'INFO':
              self.vulnerabilities.append(line['id'].upper())
        elif line['id'] == "overall_grade":                          # Grades
              self.grade.overall = line['finding']
              return                                                # return to not log as issue
        elif reCipherTLS.search(line['id']):                        # if cipher-TLS then return as not issue
              return
        elif reGradeCapReason.search(line['id']):
              self.grade.reasons.append(line['finding'])

        self.ksidentifier = (int(ipaddress.ip_address(self.ip)) / 2) + int(self.port)
        if line['severity'] != "OK" and line['severity'] != "INFO":
           m = errors.get(line['id'])
           if m != None:
             m = m.replace("%1", line['finding'])
           else:
             m = "Missing type: " + line['id'] +": " + line['finding']
           if line['severity'] == "LOW":
             self.issues.low.append(m)
           elif line['severity'] == 'MEDIUM':
             self.issues.medium.append(m)
           elif line['severity'] == 'HIGH':
             self.issues.high.append(m)
           elif line['severity'] == "CRITICAL":
             self.issues.critical.append(m)

    def parseCSV(self, csvfile):
        if self.source:
           
            m = reDefaultFilename.search(self.source)
            if m:
                self.ip = m.group('ip')
                self.port = int(m.group('port') or 0)
                self['@timestamp'] = datetime.strptime(m.group('datetime'), "%Y%m%d-%H%M")
                
            m = reDefaultHostFilename.search(self.source)
            if m:
                self.hostname = m.group('hostname')
                self.port = int(m.group('port') or 0)
                self['@timestamp'] = datetime.strptime(m.group('datetime'), "%Y%m%d-%H%M")
        csvReader = csv.DictReader(csvfile, fieldnames=("id", "fqdn/ip", "port", "severity", "finding"), delimiter=',', quotechar='"')
        for line in csvReader:
            self.parseCSVLine(line)

    def save(self, **kwargs):
        # add a timestamp if not one already
        if not hasattr(self, '@timestamp'):
            self['@timestamp'] = datetime.now(tz)
        if not self.port:
            raise ValueError("Empty scan result")

        self.svcid = "%s:%d" % (self.ip, int(self.port) or 0)
        if not self.result:
            self.result = False

        #if 'debug' in kwargs and kwargs['debug']:
        #    pp.pprint(self.to_dict())
        #pp.pprint(self.to_dict()) 
        return super().save()
#        return 
