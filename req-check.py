#!/usr/bin/env python3
"""
Checks validity of CSRs according to Switzerland RA rules for SEE-GRID CA
"""

from OpenSSL import crypto
from pyasn1.codec.der import decoder as der_decoder
from subj_alt_name import SubjectAltName
import sys
import re

ALLOWED_ORGS = (
	"ETH Zuerich",
)

# Printing functions

COLORS = {
  'HEADER': '\033[95m',
  'OKBLUE': '\033[94m',
  'OKGREEN': '\033[92m',
  'WARNING': '\033[93m',
  'FAIL': '\033[91m',
  'ENDC': '\033[0m',
  'BOLD': '\033[1m',
  'UNDERLINE': '\033[4m',
}

def out(*args, color=None, **kwargs):
	if color:
		print(COLORS[color], end='')
		print(*args, **kwargs)
		print(COLORS['ENDC'], end='', flush=True)
	else:
		print(*args, **kwargs)

def out_test(*args, check=None, **kwargs):
	out(end=' ', *args, **kwargs)
	if check:
		out('PASS', color="OKGREEN", **kwargs)
	else:
		out('FAIL', color="FAIL", **kwargs)
	return check

def subj_format(components):
	result = ""
	for pair in components:
		result += "/{}={}".format(pair[0], pair[1])
	return result

# SubjAltName

def get_subj_alt_name(req):
    '''
    Copied from ndg.httpsclient.ssl_peer_verification.ServerSSLCertVerification
    Extract subjectAltName DNS name settings from certificate extensions
    @param peer_cert: peer certificate in SSL connection.  subjectAltName
    settings if any will be extracted from this
    @type peer_cert: OpenSSL.crypto.X509
    '''
    # Search through extensions
    dns_name = []
    general_names = SubjectAltName()
    for ext in req.get_extensions():
        ext_name = ext.get_short_name()
        if ext_name == b'subjectAltName':
            # PyOpenSSL returns extension data in ASN.1 encoded form
            ext_dat = ext.get_data()
            decoded_dat = der_decoder.decode(ext_dat, asn1Spec=general_names)

            for name in decoded_dat:
                if isinstance(name, SubjectAltName):
                    for entry in range(len(name)):
                        component = name.getComponentByPosition(entry)
                        dns_name.append(str(component.getComponent()))
    return dns_name

# Checking functions

def org_type_validate(input):
	return (input == "People" or input == "Hosts")

def org_validate(input):
	return (input in ALLOWED_ORGS)

def user_name_validate(input):
	return True

def domain_name_validate(input):
	return (re.fullmatch(r'[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*', input) != None)

def pop_DN_part(components, attr_type):
	result = []
	while len(components) and components[0][0].decode("utf-8") == attr_type:
		pair = components.pop(0)
		result.append( (pair[0].decode("utf-8"), pair[1].decode("utf-8")) )
	return result

def validate_DN_part(components, attr_type, expected):
	if len(components) != len(expected):
		return False
	for i, pair in enumerate(components):
		if pair[0] != attr_type:
			return False
		if callable(expected[i]):
			if not expected[i](pair[1]):
				return False
		elif pair[1] != expected[i]:
			return False
	return True

def check_part(components, attr_type, expected):
	part = pop_DN_part(components, attr_type)
	test = validate_DN_part(part, attr_type, expected)

	out_test("{} part ({})...".format(attr_type, subj_format(part)), check=test)
	return (test, part)

def check_CSR(req):
	if not out_test("Verifying self-signature...", check=req.verify(req.get_pubkey())):
		return None

	subj = list(req.get_subject().get_components())
	out("Checking mandatory Subject fields...")

	result = check_part(subj, "DC", ("EU", "EGI"))
	if not result:
		return None

	result = check_part(subj, "C", ("CH",))
	if not result:
		return None

	result, part = check_part(subj, "O", (org_type_validate, org_validate))
	if not result:
		return None
	org = part[1][1]

	if part[0][1] == "People":
		(result, part) = check_part(subj, "CN", (user_name_validate,))
		if not result:
			return None
		else:
			return ("User", part[0][1], org)
	else:
		out("This is a Host CSR")
		(result, part) = check_part(subj, "CN", (domain_name_validate,))
		if not result:
			return None

		name = part[0][1]
		alt_names = get_subj_alt_name(req)

		if not out_test("Verifying CN in subjectAltNames...", check=(name == alt_names[0])):
			return None

		out(alt_names, color="OKBLUE")

		return ("Host", " / ".join(alt_names), org)

# Main

if __name__ == "__main__":
  if len(sys.argv) == 1:
  	sys.exit("No CSR filename(s) specified.")
  for filename in sys.argv[1:]:
  	out("\nProcessing {}...".format(filename), color="BOLD")
  	try:
  		with open(filename) as fh:
  			contents = fh.read()
  			try:
  				req = crypto.load_certificate_request(crypto.FILETYPE_PEM, contents)
  				out("Parsed PEM-encoded CSR...")
  				subject = check_CSR(req)
  				if subject:
  					out("{} is a valid {} Signature Request for:\n  {}\n    affiliated with {}.".format(filename, *subject), color="OKGREEN")
  				else:
  					out("{} is not a valid Signature Request.".format(filename), color="FAIL")
  			except crypto.Error:
  				out("{} is not a PEM-formatted CSR.".format(filename), color="FAIL")
  	except IOError:
  		out("Could not open {}.".format(filename), color="FAIL")
