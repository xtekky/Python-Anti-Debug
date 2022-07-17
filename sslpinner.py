import ssl
import socket
import OpenSSL
from difflib import SequenceMatcher


class SSLPinner:
    def __init__(self, host):
        self.host = host

    def similar(self, a, b):
        return SequenceMatcher(None, a, b).ratio()
    def get_cert(self):
        try:
            context = ssl.create_default_context()
            conn = socket.create_connection((self.host, 443))
            sock = context.wrap_socket(conn, server_hostname=self.host)
            sock.settimeout(10)
            try:
                der_cert = sock.getpeercert(True)
            finally:
                sock.close()
            return ssl.DER_cert_to_PEM_cert(der_cert)
        except:
            return False

    def pin(self):
        certificate = self.get_cert()
        if certificate is False:
            return False

        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)

        result = {
            "subject": dict(x509.get_subject().get_components()),
            "issuer": dict(x509.get_issuer().get_components()),
            "serialNumber": x509.get_serial_number(),
            "version": x509.get_version(),
        }

        extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
        extension_data = {e.get_short_name(): str(e) for e in extensions}
        result.update(extension_data)

        _str = r"{'subject': {b'CN': b'*.tiktok.com'}, 'issuer': {b'C': b'US', b'O': b'DigiCert Inc', b'CN': b'RapidSSL TLS DV RSA Mixed SHA256 2020 CA-1'}, 'serialNumber': 10563365078873817837960662065118294014, 'version': 2, b'authorityKeyIdentifier': 'keyid:A4:8D:E5:BE:7C:79:E4:70:23:6D:2E:29:34:AD:23:58:DC:F5:31:7F\n', b'subjectKeyIdentifier': '82:95:09:E5:DB:5F:56:24:04:A2:D5:CA:C6:98:02:18:7B:11:4A:D3', b'subjectAltName': 'DNS:*.tiktok.com, DNS:tiktok.com', b'keyUsage': 'Digital Signature, Key Encipherment', b'extendedKeyUsage': 'TLS Web Server Authentication, TLS Web Client Authentication', b'crlDistributionPoints': '\nFull Name:\n  URI:http://crl3.digicert.com/RapidSSLTLSDVRSAMixedSHA2562020CA-1.crl\n\nFull Name:\n  URI:http://crl4.digicert.com/RapidSSLTLSDVRSAMixedSHA2562020CA-1.crl\n', b'certificatePolicies': 'Policy: 2.23.140.1.2.1\n  CPS: http://www.digicert.com/CPS\n', b'authorityInfoAccess': 'OCSP - URI:http://ocsp.digicert.com\nCA Issuers - URI:http://cacerts.digicert.com/RapidSSLTLSDVRSAMixedSHA2562020CA-1.crt\n', b'basicConstraints': 'CA:FALSE', b'ct_precert_scts': 'Signed Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 29:79:BE:F0:9E:39:39:21:F0:56:73:9F:63:A5:77:E5:\n                BE:57:7D:9C:60:0A:F8:F9:4D:5D:26:5C:25:5D:C7:84\n    Timestamp : Aug 20 06:34:51.301 2021 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:44:02:20:3E:E4:D6:59:EC:22:65:35:0B:56:33:D3:\n                55:C6:E6:3D:48:C5:4A:D0:BA:8D:FD:6E:0F:9B:90:0A:\n                8A:73:FC:DB:02:20:6E:4B:5E:EA:EF:EE:AD:A9:FA:F1:\n                77:2E:28:87:58:D1:AF:C3:9B:96:6D:CB:19:80:03:CF:\n                A7:7D:6C:49:55:88\nSigned Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 51:A3:B0:F5:FD:01:79:9C:56:6D:B8:37:78:8F:0C:A4:\n                7A:CC:1B:27:CB:F7:9E:88:42:9A:0D:FE:D4:8B:05:E5\n    Timestamp : Aug 20 06:34:51.407 2021 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:46:02:21:00:FA:94:CD:71:C1:9D:58:0F:26:84:7C:\n                BF:E9:28:BB:AF:89:8C:DB:19:C3:4C:CA:E5:A0:62:D2:\n                FB:3E:24:1E:9B:02:21:00:AC:D4:22:35:BC:09:5C:9E:\n                89:10:A9:4B:AA:B1:2D:32:D3:E1:55:67:5E:F9:CF:F0:\n                25:D0:1C:5B:72:06:AC:C2\nSigned Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 41:C8:CA:B1:DF:22:46:4A:10:C6:A1:3A:09:42:87:5E:\n                4E:31:8B:1B:03:EB:EB:4B:C7:68:F0:90:62:96:06:F6\n    Timestamp : Aug 20 06:34:51.325 2021 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:46:02:21:00:91:61:96:CC:4F:6E:0D:C1:2A:EF:25:\n                06:89:BB:2B:DB:71:31:45:F8:A9:20:04:B7:4C:CB:28:\n                1E:A8:47:DA:48:02:21:00:82:77:71:59:94:7C:B1:F8:\n                B7:79:14:05:0B:A1:C5:AD:05:08:F1:C8:C1:B8:6A:7A:\n                CA:3B:6A:A1:54:52:C9:B7'}"

        if if self.similar(str(result), _str) > 0.8:
            return True
        else:
            return False


if __name__ == "__main__":
    if SSLPinner("tiktok.com").pin():
        print("This connection is secure")
    else:
        print("This connection is not secure, fuck u skid")
