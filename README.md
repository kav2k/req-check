# req-check

Validates CSRs according to SEE-GRID CA rules

## Required packages

Requirements (in terms of Debian packages): python3, python3-openssl
Requirements (in terms of Python packages): pyopenssl, pyasn1

## Usage

    ./req-check.py file1.pem [file2.pem ...]
    
## Configuration

Check-rules are hardcoded; to modify the list of allowed organizations, edit `ALLOWED_ORGS` at the top of `req-check.py`

## Credits

* `subj_alt_name.py` from some version of `ndg-httpsclient` package (with modification),  
  (c) 2012 Science and Technology Facilities Council, under BSD license
* `get_subj_alt_name`@`req-check.py` from [this Gist](https://gist.github.com/cato-/6551668),  
  (c) ? dev@robertweidlich.de, under "THE BEER-WARE LICENSE" (Revision 42)
