A Python tool for parsing MediaTek PRELOADER binaries to generate UEFI-compliant memory maps for embedded systems. It extracts and validates memory configurations, corrects size mismatches, assigns base addresses, and applies UEFI attributes, ensuring robust compatibility across MediaTek devices. Ideal for firmware developers and embedded systems engineers.

How to use 

git clone https://github.com/saidanimelek26/MediaTekMemoryMapper-edk2

pip install capstone

python MTKPreloaderParser.py preloader.bin
