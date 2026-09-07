# Function identity verification

`identity.py` classifies resolved addresses against a function-match index.
`verify_identity.py` supplies the command-line entry point.

Each binary has its own image base. Keep those address spaces separate when
converting absolute addresses into image-relative offsets. A unique pattern
match alone does not prove that it resolved to the intended function.

Run `python tools/identity/verify_identity.py --help` for required inputs.
