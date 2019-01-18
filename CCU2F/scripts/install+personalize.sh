#!/bin/bash
# Install applet and set private key of attestation certifcate (User Presence Check disabled)
#java -jar tools/gp.jar -reinstall ccu2f.cap -params 010140f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664

# Install applet and set private key of attestation certifcate (User Presence Check enabled)
java -jar tools/gp.jar -reinstall cap/ccu2f.cap -params 000140f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664

# Upload attestation certificate
scriptor scripts/personalisation_script.txt
