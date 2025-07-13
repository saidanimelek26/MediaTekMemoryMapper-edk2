#!/usr/bin/env python3
import struct
import binascii
import logging
import argparse
import os
from typing import Dict, List, Tuple, Optional, Set
from pathlib import Path

class MTKPreloaderAnalyzer:
    def __init__(self):
        self.logger = self._setup_logging()
        self._init_patterns()
        self._init_element_structures()
        self._init_common_regions()

    def _setup_logging(self):
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
        """Initialize all known header patterns with priority order"""
        self.header_patterns = [
            b"MTK_BLOADER_INFO",      # Most common standard
            b"MTK_BLDR_INFO",         # Shortened version
            b"MTK_BOOTLOADER_INFO",   # Extended version
            b"MTK_BL_INFO",           # Alternative pattern
            b"BLOADER_INFO",          # Without MTK prefix
            b"MM_BLOADER_INFO",       # Newer format
            b"MTK_PRELOADER_INFO",    # Preloader specific
            b"MTK_BL_HEADER",         # Alternative header
            b"MTK_BL_V2_INFO",        # Version 2 format
            b"MTK_BOOT",              # Fallback pattern
            b"MTK_LOADER",            # Basic fallback
            b"BLOADER_V",             # Alternative variant
            b"MTK_MM_BL"              # New MediaTek pattern
        ]

    def _init_element_structures(self):
        """Define all known element structures"""
        self.element_structures = [
            {'size': 188, 'offsets': {'emi_cona': 28, 'dram_sizes': 36}},
            {'size': 196, 'offsets': {'emi_cona': 32, 'dram_sizes': 40}},
            {'size': 200, 'offsets': {'emi_cona': 32, 'dram_sizes': 44}},
            {'size': 184, 'offsets': {'emi_cona': 28, 'dram_sizes': 36}},
            {'size': 192, 'offsets': {'emi_cona': 30, 'dram_sizes': 38}}
        ]

    def _init_common_regions(self):
        """Initialize standard memory regions"""
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

    def analyze(self, preloader_file: str, output_dir: str = None):
        """Main analysis workflow with enhanced error recovery"""
        try:
            data = self._read_preloader(preloader_file)
            
            # First try standard analysis
            header_offset = self._find_header(data)
            if header_offset == -1:
                self.logger.warning("Standard header not found, attempting deep scan")
                return self._deep_scan_analysis(data, output_dir)

            elements = self._parse_all_elements(data, header_offset)
            if not elements:
                self.logger.warning("No elements found via standard method")
                return self._deep_scan_analysis(data, output_dir)

            memory_map = self._generate_memory_map(elements)
            output_file = self._get_output_path(preloader_file, output_dir)
            self._write_memory_map(memory_map, output_file)

            self.logger.info(f"Successfully generated memory map at {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            return False

    def _read_preloader(self, filename: str) -> bytes:
        """Read preloader file with validation"""
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Preloader file not found: {filename}")

        file_size = os.path.getsize(filename)
        if file_size < 0x40000:
            self.logger.warning(f"File size ({file_size} bytes) seems small for a preloader")

        with open(filename, 'rb') as f:
            return f.read()

    def _find_header(self, data: bytes) -> int:
        """Enhanced header detection with multiple scan methods"""
        common_offsets = [0x0, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000]
        for offset in common_offsets:
            if offset + 16 > len(data):
                continue
                
            for pattern in self.header_patterns:
                if data[offset:offset+len(pattern)] == pattern:
                    self.logger.info(f"Found header '{pattern.decode('ascii', errors='ignore')}' at 0x{offset:08X}")
                    return offset

        for pattern in self.header_patterns:
            offset = data.find(pattern)
            if offset != -1:
                self.logger.info(f"Found header '{pattern.decode('ascii', errors='ignore')}' at 0x{offset:08X}")
                return offset

        for pattern in self.header_patterns:
            if len(pattern) < 8:
                continue
            partial = pattern[-8:]
            offset = data.find(partial)
            if offset != -1:
                self.logger.warning(f"Found partial header match '{partial.decode('ascii', errors='ignore')}' at 0x{offset:08X}")
                return offset - (len(pattern) - 8)

        return -1

    def _deep_scan_analysis(self, data: bytes, output_dir: str) -> bool:
        """Comprehensive fallback analysis when standard methods fail"""
        self.logger.info("Starting deep scan analysis...")
        
        elements = self._find_elements_by_pattern(data)
        
        if len(elements) < 2:  
            elements = self._find_dram_configurations(data)
        
        if elements:
            
            elements = self._filter_elements(elements)
            elements = self._merge_similar_elements(elements)
            
            elements = sorted(elements, key=lambda x: x['total_dram_mb'], reverse=True)
            
            memory_map = self._generate_memory_map(elements)
            output_file = os.path.join(output_dir, "deep_scan_memory_map.c") if output_dir else "deep_scan_memory_map.c"
            self._write_memory_map(memory_map, output_file)
            self.logger.info(f"Generated memory map using deep scan at {output_file}")
            return True
        
        self.logger.error("Deep scan failed to identify valid memory configuration")
        return False

    def _merge_similar_elements(self, elements: List[Dict]) -> List[Dict]:
        """Merge similar/duplicate elements"""
        if not elements:
            return []
            
        elements.sort(key=lambda x: x['total_dram_mb'])
        merged = []
        current = elements[0]
        
        for elem in elements[1:]:
            size_diff = abs(current['total_dram_mb'] - elem['total_dram_mb'])
            if size_diff < (current['total_dram_mb'] * 0.1): 
                current['total_dram_mb'] = max(current['total_dram_mb'], elem['total_dram_mb'])
            else:
                merged.append(current)
                current = elem
                
        merged.append(current)
        
        self.logger.info(f"Merged {len(elements)} elements down to {len(merged)}")
        return merged

    def _filter_elements(self, elements: List[Dict]) -> List[Dict]:
        """Filter out duplicate and invalid elements"""
        filtered = []
        seen_offsets = set()
        seen_sizes = set()
        
        for elem in elements:
            # 
            if elem['offset'] in seen_offsets:
                continue
            seen_offsets.add(elem['offset'])
            
            # 
            if not (64 <= elem['total_dram_mb'] <= 16384):  # 
                continue
                
            # 
            if elem['total_dram_mb'] in seen_sizes:
                continue
            seen_sizes.add(elem['total_dram_mb'])
                
            filtered.append(elem)
        
        self.logger.info(f"Filtered {len(elements)} elements down to {len(filtered)}")
        return filtered

    def _find_elements_by_pattern(self, data: bytes) -> List[Dict]:
        """Find memory elements by scanning for characteristic patterns with stricter validation"""
        elements = []
        min_element_size = 160  # 
        
        for struct_def in self.element_structures:
            self.logger.debug(f"Scanning with structure size {struct_def['size']}")
            for i in range(0, len(data) - min_element_size, 4):
                try:
                    emi_cona = struct.unpack_from('<I', data, i + struct_def['offsets']['emi_cona'])[0]
                    dram_sizes = struct.unpack_from('<4I', data, i + struct_def['offsets']['dram_sizes'])
                    
                    # 
                    if emi_cona == 0 or all(size == 0 for size in dram_sizes):
                        continue
                        
                    # 
                    if any(size > 0x100000000 for size in dram_sizes):  # >4GB per rank is unlikely
                        continue
                        
                    total_mb = sum(size//(1024*1024) for size in dram_sizes if size > 0)
                    
                    # 
                    if not (64 <= total_mb <= 16384):  # 
                        continue
                        
                    # 
                    nonzero_sizes = [s for s in dram_sizes if s > 0]
                    if max(nonzero_sizes) / min(nonzero_sizes) > 8:  # 
                        continue
                        
                    elements.append({
                        'index': len(elements),
                        'offset': i,
                        'emi_cona': emi_cona,
                        'dram_rank_size': dram_sizes,
                        'total_dram_mb': total_mb,
                        'detection_method': 'pattern_scan',
                        'structure_size': struct_def['size']
                    })
                    
                except Exception as e:
                    continue
        
        return elements

    def _find_dram_configurations(self, data: bytes) -> List[Dict]:
        """Alternative method to find DRAM configurations with stricter validation"""
        elements = []
        dram_config_patterns = [
            b"\x00\x00\x00\x80",  # 
            b"\x00\x00\x01\x00",
            b"\x00\x00\x02\x00"
        ]
        
        for pattern in dram_config_patterns:
            pos = -1
            while True:
                pos = data.find(pattern, pos+1)
                if pos == -1 or pos + 64 > len(data):
                    break
                
                try:
                    dram_sizes = struct.unpack_from('<4I', data, pos+16)
                    if all(size == 0 for size in dram_sizes):
                        continue
                        
                    total_mb = sum(size//(1024*1024) for size in dram_sizes if size > 0)
                    
                    # 
                    if not (128 <= total_mb <= 8192):  # 128MB - 8GB
                        continue
                        
                    # 
                    nonzero_sizes = [s for s in dram_sizes if s > 0]
                    if len(nonzero_sizes) > 1 and (max(nonzero_sizes) / min(nonzero_sizes) > 4):
                        continue
                        
                    elements.append({
                        'index': len(elements),
                        'offset': pos,
                        'emi_cona': 0x80000000,  # Default value
                        'dram_rank_size': dram_sizes,
                        'total_dram_mb': total_mb,
                        'detection_method': 'dram_pattern'
                    })
                except:
                    continue
        
        return elements

    def _parse_all_elements(self, data: bytes, header_offset: int) -> List[Dict]:
        """Parse all memory elements with flexible structure detection"""
        elements = []
        
        # 
        for element_count in [12, 16, 8, 24]:
            elements = []
            valid_elements = 0
            
            for i in range(element_count):
                # 
                for struct_def in self.element_structures:
                    elem_offset = header_offset + 0x70 + (i * struct_def['size'])
                    element = self._parse_element(data, elem_offset, struct_def)
                    if element and element.get('total_dram_mb', 0) > 0:
                        element['index'] = i
                        elements.append(element)
                        valid_elements += 1
                        break
            
            if valid_elements >= 4:  # 
                self.logger.info(f"Found {valid_elements} valid elements with size {struct_def['size']} bytes")
                break
        
        return elements

    def _parse_element(self, data: bytes, offset: int, struct_def: Dict) -> Optional[Dict]:
        """Parse memory element with flexible structure"""
        try:
            if offset + struct_def['size'] > len(data):
                return None

            emi_cona = struct.unpack_from('<I', data, offset + struct_def['offsets']['emi_cona'])[0]
            dram_sizes = struct.unpack_from('<4I', data, offset + struct_def['offsets']['dram_sizes'])

            # 
            if all(s == 0 for s in dram_sizes) or emi_cona == 0:
                return None
                
            # 
            if any(size > 0x100000000 for size in dram_sizes):  # 
                return None

            total_mb = sum(s//(1024*1024) for s in dram_sizes if s > 0)
            
            # 
            if not (64 <= total_mb <= 16384):  # 
                return None
                
            # 
            nonzero_sizes = [s for s in dram_sizes if s > 0]
            if len(nonzero_sizes) > 1 and (max(nonzero_sizes) / min(nonzero_sizes) > 8):
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
        """Generate complete memory map with smart region placement"""
        regions = []
        used_addresses = set()
        total_dram = sum(e.get('total_dram_mb', 0) for e in elements)

        #
        for region in self.common_regions:
            regions.append(region)
            used_addresses.add((region['base'], region['base'] + region['size']))

        #
        sorted_elements = sorted(elements, key=lambda x: x['total_dram_mb'], reverse=True)

        #
        current_address = 0x40000000  
        for element in sorted_elements:
            if not element.get('total_dram_mb', 0):
                continue

            size = element['total_dram_mb'] * 1024 * 1024
            try:
                #
                current_address = (current_address + 0xFFFFF) & ~0xFFFFF
                
                #
                overlap = False
                for (start, end) in used_addresses:
                    if not (current_address + size <= start or current_address >= end):
                        overlap = True
                        break
                
                if overlap:
                    #
                    if used_addresses:
                        last_end = max(end for (start, end) in used_addresses)
                        current_address = (last_end + 0xFFFFF) & ~0xFFFFF
                    else:
                        current_address = 0x40000000

                regions.append({
                    'label': f"DRAM_{element['index']}",
                    'base': current_address,
                    'size': size,
                    'build_hob': "AddMem",
                    'res_type': "SYS_MEM",
                    'res_attr': "SYS_MEM_CAP",
                    'mem_type': "Conv",
                    'cache_attr': "WRITE_BACK_XN",
                    'comment': f"Detected via {element.get('detection_method', 'standard')}"
                })
                
                used_addresses.add((current_address, current_address + size))
                current_address += size
            except ValueError as e:
                self.logger.warning(f"Could not place DRAM region of size {size//(1024*1024)}MB: {str(e)}")
                continue

        #
        uefi_regions = self._get_uefi_regions(total_dram)
        for region in uefi_regions:
            size = region['size']
            try:
                #
                base = 0x1B000000 if not used_addresses else max(end for (start, end) in used_addresses)
                base = (base + 0xFFFFF) & ~0xFFFFF  #
                
                #
                while True:
                    overlap = False
                    for (start, end) in used_addresses:
                        if not (base + size <= start or base >= end):
                            overlap = True
                            break
                    if not overlap:
                        break
                    base = (end + 0xFFFFF) & ~0xFFFFF
                
                new_region = region.copy()
                new_region['base'] = base
                regions.append(new_region)
                used_addresses.add((base, base + size))
            except ValueError as e:
                self.logger.warning(f"Could not place UEFI region: {str(e)}")
                continue

        #
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

    def _get_uefi_regions(self, total_dram_mb: int) -> List[Dict]:
        """Get UEFI regions with size adjusted based on total DRAM"""
        #
        scale_factor = min(max(total_dram_mb / 2048, 0.5), 2.0)  # Between 0.5x and 2.0x
        
        return [
            {
                'label': "UEFI Stack",
                'size': int(0x00040000 * scale_factor),
                'build_hob': "AddMem",
                'res_type': "SYS_MEM",
                'res_attr': "SYS_MEM_CAP",
                'mem_type': "BsData",
                'cache_attr': "WRITE_BACK"
            },
            {
                'label': "CPU Vectors",
                'size': int(0x00010000 * scale_factor),
                'build_hob': "AddMem",
                'res_type': "SYS_MEM",
                'res_attr': "SYS_MEM_CAP",
                'mem_type': "BsCode",
                'cache_attr': "WRITE_BACK"
            },
            {
                'label': "DXE Heap",
                'size': int(0x08000000 * scale_factor),  # 128MB base size
                'build_hob': "AddMem",
                'res_type': "SYS_MEM",
                'res_attr': "SYS_MEM_CAP",
                'mem_type': "Conv",
                'cache_attr': "WRITE_BACK"
            }
        ]

    def _get_output_path(self, input_file: str, output_dir: str = None) -> str:
        """Determine output file path"""
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            base_name = os.path.basename(input_file)
            return os.path.join(output_dir, f"PlatformMemoryMap_{os.path.splitext(base_name)[0]}.c")
        return f"PlatformMemoryMap_{os.path.splitext(os.path.basename(input_file))[0]}.c"

    def _write_memory_map(self, regions: List[Dict], filename: str):
        """Write memory map to C source file"""
        with open(filename, 'w') as f:
            f.write("/**\n")
            f.write(" * Auto-generated memory map from MTK preloader analysis\n")
            f.write(" * This file contains the memory layout for UEFI firmware\n")
            f.write(" */\n\n")
            f.write("#include <Library/BaseLib.h>\n")
            f.write("#include <Library/PlatformMemoryMapLib.h>\n\n")
            
            f.write("static ARM_MEMORY_REGION_DESCRIPTOR_EX gDeviceMemoryDescriptorEx[] = {\n")
            f.write("    /* Label                     Base            Size            BuildHob   ResType        ResAttr           MemType     CacheAttr       */\n")
            
            for region in regions:
                f.write(f"    {{\"{region['label']}\",".ljust(34))
                f.write(f" 0x{region['base']:08X},".ljust(14))
                f.write(f" 0x{region['size']:08X},".ljust(14))
                f.write(f" {region['build_hob']},".ljust(10))
                f.write(f" {region['res_type']},".ljust(14))
                f.write(f" {region['res_attr']},".ljust(18))
                f.write(f" {region['mem_type']},".ljust(10))
                f.write(f" {region['cache_attr']}")
                if 'comment' in region:
                    f.write(f", /* {region['comment']} */")
                f.write("},\n")
            
            f.write("};\n\n")
            f.write("ARM_MEMORY_REGION_DESCRIPTOR_EX *GetPlatformMemoryMap()\n")
            f.write("{\n")
            f.write("    return gDeviceMemoryDescriptorEx;\n")
            f.write("}\n")

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced MTK Preloader Analyzer with Improved Memory Placement",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("preloader", help="Path to preloader image file")
    parser.add_argument("-o", "--output", help="Output directory for generated files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debugging")
    args = parser.parse_args()

    analyzer = MTKPreloaderAnalyzer()
    if args.verbose:
        analyzer.logger.setLevel(logging.DEBUG)

    if not analyzer.analyze(args.preloader, args.output):
        analyzer.logger.error("Analysis completed with errors")
        exit(1)

if __name__ == "__main__":
    main()