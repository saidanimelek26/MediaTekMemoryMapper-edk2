#!/usr/bin/env python3
import struct
import binascii
import logging
import argparse
import os
import sys
from typing import Dict, List, Tuple, Optional, Set
from pathlib import Path

class MTKPreloaderAnalyzer:
    def __init__(self):
        self.logger = self._setup_logging()
        self._init_patterns()
        self._init_element_structures()
        self._init_common_regions()
        self._init_reserved_regions()

    def _setup_logging(self):
        """Configure logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler("preloader_analysis.log"),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def _init_patterns(self):
        """Initialize known MTK header patterns"""
        self.header_patterns = [
            b"MTK_BLOADER_INFO",
            b"MTK_BLDR_INFO",
            b"MTK_BOOTLOADER_INFO",
            b"MTK_BL_INFO",
            b"BLOADER_INFO",
            b"MM_BLOADER_INFO",
            b"MMM",
            b"\x4D\x4D\x4D"
        ]

    def _init_element_structures(self):
        """Define memory element structures"""
        self.element_structures = [
            {'size': 188, 'offsets': {'emi_cona': 28, 'dram_sizes': 36}},
            {'size': 196, 'offsets': {'emi_cona': 32, 'dram_sizes': 40}},
            {'size': 184, 'offsets': {'emi_cona': 24, 'dram_sizes': 32}},
            {'size': 200, 'offsets': {'emi_cona': 36, 'dram_sizes': 44}}
        ]

    def _init_common_regions(self):
        """Standard memory regions for MTK devices"""
        self.common_regions = [
            {
                'label': "Peripherals",
                'base': 0x00000000,
                'size': 0x1B000000,
                'build_hob': "AddMem",
                'res_type': "MEM_RES",
                'res_attr': "UNCACHEABLE",
                'mem_type': "RtCode",
                'cache_attr': "NS_DEVICE",
                'fixed': True
            }
        ]

    def _init_reserved_regions(self):
        """Reserved regions with updated addresses"""
        self.reserved_regions = [
            {
                'label': "TEE Reserved",
                'base': 0x7CD00000,
                'size': 0x03200000,
                'build_hob': "AddMem",
                'res_type': "MEM_RES",
                'res_attr': "SYS_MEM_CAP",
                'mem_type': "Reserv",
                'cache_attr': "WRITE_BACK",
                'fixed': False
            },
            {
                'label': "Display Reserved",
                'base': 0x7BEE0000,
                'size': 0x00E20000,
                'build_hob': "AddMem",
                'res_type': "MEM_RES",
                'res_attr': "SYS_MEM_CAP",
                'mem_type': "Reserv",
                'cache_attr': "WRITE_THROUGH_XN",
                'fixed': False
            }
        ]

    def analyze(self, preloader_file: str, output_dir: str = None):
        """Main analysis workflow"""
        try:
            self.logger.info(f"Analyzing preloader file: {preloader_file}")
            data = self._read_preloader(preloader_file)
            
            header_offset = self._find_header(data)
            if header_offset == -1:
                self.logger.warning("Header not found, using default memory map")
                memory_map = self._generate_default_memory_map()
            else:
                elements = self._parse_all_elements(data, header_offset)
                if not elements:
                    self.logger.warning("No valid elements found, using default memory map")
                    memory_map = self._generate_default_memory_map()
                else:
                    memory_map = self._generate_memory_map(elements)

            output_file = self._get_output_path(preloader_file, output_dir)
            self._write_memory_map(memory_map, output_file)
            self.logger.info(f"Memory map generated at {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            return False

    def _read_preloader(self, filename: str) -> bytes:
        """Read preloader file with validation"""
        try:
            MAX_FILE_SIZE = 16 * 1024 * 1024
            if not os.path.exists(filename):
                raise FileNotFoundError(f"File does not exist: {filename}")
            
            file_size = os.path.getsize(filename)
            if file_size == 0:
                raise ValueError("File is empty (0 bytes)")
            if file_size > MAX_FILE_SIZE:
                raise ValueError(f"File too large (>{MAX_FILE_SIZE} bytes)")
            
            with open(filename, 'rb') as f:
                data = f.read()
                if len(data) != file_size:
                    raise IOError(f"File read incomplete: expected {file_size} bytes, got {len(data)}")
                return data
        except Exception as e:
            self.logger.error(f"Failed to read preloader file: {str(e)}")
            raise

    def _find_header(self, data: bytes) -> int:
        """Find preloader header"""
        for offset in [0x0, 0x400, 0x800, 0x1000, 0x2000]:
            if offset + 16 > len(data):
                continue
            for pattern in self.header_patterns:
                if data[offset:offset+len(pattern)] == pattern:
                    self.logger.info(f"Found header '{pattern.decode('ascii', errors='ignore')}' at 0x{offset:08X}")
                    return offset
        return -1

    def _parse_all_elements(self, data: bytes, header_offset: int) -> List[Dict]:
        """Parse all memory elements"""
        elements = []
        for i in range(12):  # Try up to 12 elements
            for struct_def in self.element_structures:
                elem_offset = header_offset + 0x70 + (i * struct_def['size'])
                element = self._parse_element(data, elem_offset, struct_def)
                if element and element.get('total_dram_mb', 0) > 0:
                    elements.append(element)
                    break
        return elements

    def _parse_element(self, data: bytes, offset: int, struct_def: Dict) -> Optional[Dict]:
        """Parse single memory element"""
        try:
            if offset + struct_def['size'] > len(data):
                return None

            emi_cona = struct.unpack_from('<I', data, offset + struct_def['offsets']['emi_cona'])[0]
            dram_sizes = struct.unpack_from('<4I', data, offset + struct_def['offsets']['dram_sizes'])

            total_mb = sum(s//(1024*1024) for s in dram_sizes if s > 0)
            if not (64 <= total_mb <= 8192):  # Validate DRAM size
                return None

            return {
                'offset': offset,
                'emi_cona': emi_cona,
                'dram_rank_size': dram_sizes,
                'total_dram_mb': total_mb,
                'structure_size': struct_def['size']
            }
        except Exception as e:
            self.logger.debug(f"Failed to parse element at 0x{offset:08X}: {str(e)}")
            return None

    def _generate_memory_map(self, elements: List[Dict]) -> List[Dict]:
        """Generate memory map"""
        regions = []
        used_addresses = set()
        
        # Add fixed regions
        for region in self.common_regions:
            regions.append(region)
            used_addresses.add((region['base'], region['base'] + region['size']))
        
        # Add DRAM regions
        current_address = 0x40000000
        for element in elements:
            size = element['total_dram_mb'] * 1024 * 1024
            current_address = (current_address + 0xFFFFF) & ~0xFFFFF  # Align
            
            # Check for overlaps
            overlap = False
            for (start, end) in used_addresses:
                if not (current_address + size <= start or current_address >= end):
                    overlap = True
                    break
            
            if not overlap and size > 0:
                regions.append({
                    'label': f"DRAM {len([r for r in regions if 'DRAM' in r['label']])}",
                    'base': current_address,
                    'size': size,
                    'build_hob': "AddMem",
                    'res_type': "SYS_MEM",
                    'res_attr': "SYS_MEM_CAP",
                    'mem_type': "Conv",
                    'cache_attr': "WRITE_BACK_XN"
                })
                used_addresses.add((current_address, current_address + size))
                current_address += size
        
        # Add reserved regions if they don't overlap
        for region in self.reserved_regions:
            overlap = False
            for (start, end) in used_addresses:
                if not (region['base'] + region['size'] <= start or region['base'] >= end):
                    overlap = True
                    break
            
            if not overlap:
                regions.append(region)
                used_addresses.add((region['base'], region['base'] + region['size']))
        
        # Add UEFI regions
        self._add_uefi_regions(regions, used_addresses)
        
        # Add terminator
        regions.append({
            'label': "Terminator",
            'base': 0,
            'size': 0,
            'build_hob': "0",
            'res_type': "0",
            'res_attr': "0",
            'mem_type': "0",
            'cache_attr': "0"
        })
        
        return sorted(regions, key=lambda x: x['base'])

    def _add_uefi_regions(self, regions: List[Dict], used_addresses: Set[Tuple[int, int]]):
        """Add UEFI regions"""
        uefi_regions = [
            {'label': "UEFI Stack", 'size': 0x00040000, 'mem_type': "BsData"},
            {'label': "CPU Vectors", 'size': 0x00010000, 'mem_type': "BsCode"},
            {'label': "DXE Heap", 'size': 0x01000000, 'mem_type': "Conv"}
        ]
        
        # Find last DRAM region
        last_dram = next((r for r in reversed(regions) if 'DRAM' in r['label']), None)
        if last_dram:
            base = last_dram['base'] + last_dram['size']
            
            for region in uefi_regions:
                base = (base + 0xFFFFF) & ~0xFFFFF  # Align
                regions.append({
                    'label': region['label'],
                    'base': base,
                    'size': region['size'],
                    'build_hob': "AddMem",
                    'res_type': "SYS_MEM",
                    'res_attr': "SYS_MEM_CAP",
                    'mem_type': region['mem_type'],
                    'cache_attr': "WRITE_BACK"
                })
                base += region['size']

    def _generate_default_memory_map(self) -> List[Dict]:
        """Generate default memory map"""
        regions = []
        regions.extend(self.common_regions)
        
        # Add default DRAM (4GB)
        regions.append({
            'label': "DRAM 0",
            'base': 0x40000000,
            'size': 0x100000000,
            'build_hob': "AddMem",
            'res_type': "SYS_MEM",
            'res_attr': "SYS_MEM_CAP",
            'mem_type': "Conv",
            'cache_attr': "WRITE_BACK_XN"
        })
        
        # Add UEFI regions
        self._add_uefi_regions(regions, set())
        
        # Add terminator
        regions.append({
            'label': "Terminator",
            'base': 0,
            'size': 0,
            'build_hob': "0",
            'res_type': "0",
            'res_attr': "0",
            'mem_type': "0",
            'cache_attr': "0"
        })
        
        return regions

    def _get_output_path(self, input_file: str, output_dir: str = None) -> str:
        """Get output file path"""
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            base_name = os.path.basename(input_file)
            return os.path.join(output_dir, f"PlatformMemoryMap_{os.path.splitext(base_name)[0]}.c")
        return f"PlatformMemoryMap_{os.path.splitext(os.path.basename(input_file))[0]}.c"

    def _write_memory_map(self, regions: List[Dict], filename: str):
        """Write memory map to file"""
        try:
            with open(filename, 'w') as f:
                f.write("/**\n * Auto-generated memory map\n */\n\n")
                f.write("#include <Library/BaseLib.h>\n")
                f.write("#include <Library/PlatformMemoryMapLib.h>\n\n")
                f.write("static ARM_MEMORY_REGION_DESCRIPTOR_EX gDeviceMemoryDescriptorEx[] = {\n")
                f.write("    /* Label, Base, Size, BuildHob, ResType, ResAttr, MemType, CacheAttr */\n")
                
                for region in regions:
                    f.write(f"    {{\"{region['label']}\", 0x{region['base']:08X}, 0x{region['size']:08X}, "
                           f"{region['build_hob']}, {region['res_type']}, {region['res_attr']}, "
                           f"{region['mem_type']}, {region['cache_attr']}")
                    if region['label'] != "Terminator":
                        f.write("},\n")
                    else:
                        f.write("}\n")
                
                f.write("};\n\n")
                f.write("ARM_MEMORY_REGION_DESCRIPTOR_EX *GetPlatformMemoryMap()\n{\n    return gDeviceMemoryDescriptorEx;\n}\n")
        except IOError as e:
            self.logger.error(f"Failed to write output file: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description="MTK Preloader Memory Map Generator")
    parser.add_argument("preloader", help="Path to preloader image file")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    analyzer = MTKPreloaderAnalyzer()
    if args.verbose:
        analyzer.logger.setLevel(logging.DEBUG)

    if not analyzer.analyze(args.preloader, args.output):
        sys.exit(1)

if __name__ == "__main__":
    main()
