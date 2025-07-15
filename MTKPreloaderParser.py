from dataclasses import dataclass
from typing import List, Optional
import json
import struct

# Define constants for UEFI/ARM memory attributes
class ResourceType:
    SYS_MEM = "SYS_MEM"
    MEM_RES = "MEM_RES"

class ResourceAttribute:
    SYS_MEM_CAP = "SYS_MEM_CAP"
    UNCACHEABLE = "UNCACHEABLE"

class MemoryType:
    Conv = "Conventional"
    BsCode = "BootServiceCode"
    RtCode = "RuntimeCode"
    Reserv = "Reserved"

class CacheAttributes:
    WRITE_BACK = "WRITE_BACK"
    WRITE_BACK_XN = "WRITE_BACK_XN"
    WRITE_THROUGH_XN = "WRITE_THROUGH_XN"
    NS_DEVICE = "NS_DEVICE"
    UNCACHEABLE = "UNCACHEABLE"

# Data class for memory regions (similar to ARM_MEMORY_REGION_DESCRIPTOR_EX)
@dataclass
class MemoryRegion:
    label: str
    base_address: int
    size: int
    build_hob: str = "AddMem"
    resource_type: str = ResourceType.SYS_MEM
    resource_attribute: str = ResourceAttribute.SYS_MEM_CAP
    memory_type: str = MemoryType.Conv
    cache_attributes: str = CacheAttributes.WRITE_BACK

    def to_dict(self):
        """Convert MemoryRegion to dictionary for JSON export."""
        return {
            "label": self.label,
            "base_address": f"0x{self.base_address:08X}",
            "size": f"0x{self.size:08X}",
            "build_hob": self.build_hob,
            "resource_type": self.resource_type,
            "resource_attribute": self.resource_attribute,
            "memory_type": self.memory_type,
            "cache_attributes": self.cache_attributes
        }

# Placeholder function to parse preloader and extract memory regions
def parse_preloader_memory_regions() -> List[MemoryRegion]:
    """
    Simulates parsing a preloader to extract memory regions.
    Replace with actual logic to parse your preloader (e.g., binary file, JSON, firmware API).
    """
    try:
        # Example regions (replace with actual preloader data)
        regions = [
            MemoryRegion(
                label="Peripherals",
                base_address=0x00000000,
                size=0x1B000000,  # 432 MB
                resource_type=ResourceType.MEM_RES,
                resource_attribute=ResourceAttribute.UNCACHEABLE,
                memory_type=MemoryType.RtCode,
                cache_attributes=CacheAttributes.NS_DEVICE
            ),
            MemoryRegion(
                label="DDR Memory 1",
                base_address=0x40000000,
                size=0x10000000,  # 256 MB
                resource_type=ResourceType.SYS_MEM,
                resource_attribute=ResourceAttribute.SYS_MEM_CAP,
                memory_type=MemoryType.Conv,
                cache_attributes=CacheAttributes.WRITE_BACK
            ),
            MemoryRegion(
                label="Frame Buffer",
                base_address=0x50000000,
                size=0x01000000,  # 16 MB
                resource_type=ResourceType.MEM_RES,
                resource_attribute=ResourceAttribute.SYS_MEM_CAP,
                memory_type=MemoryType.Reserv,
                cache_attributes=CacheAttributes.WRITE_THROUGH_XN
            ),
            MemoryRegion(
                label="Reserved TEE",
                base_address=0x51000000,
                size=0x02000000,  # 32 MB
                resource_type=ResourceType.MEM_RES,
                resource_attribute=ResourceAttribute.SYS_MEM_CAP,
                memory_type=MemoryType.Reserv,
                cache_attributes=CacheAttributes.WRITE_BACK
            )
        ]
        return regions
    except Exception as e:
        print(f"Error parsing preloader: {str(e)}")
        return []

# Example: Parsing a binary preloader file (uncomment and customize as needed)
"""
def parse_preloader_memory_regions() -> List[MemoryRegion]:
    # Example: Parse a binary preloader file
    # Assumes format: [4-byte region count][32-byte label][8-byte base][8-byte size][16-byte types/attrs...]
    regions = []
    try:
        with open("preloader.bin", "rb") as f:
            region_count = struct.unpack("<I", f.read(4))[0]
            for _ in range(region_count):
                label = f.read(32).decode("utf-8").rstrip("\x00")
                base_address = struct.unpack("<Q", f.read(8))[0]
                size = struct.unpack("<Q", f.read(8))[0]
                resource_type = f.read(16).decode("utf-8").rstrip("\x00")
                resource_attribute = f.read(16).decode("utf-8").rstrip("\x00")
                memory_type = f.read(16).decode("utf-8").rstrip("\x00")
                cache_attributes = f.read(16).decode("utf-8").rstrip("\x00")
                regions.append(MemoryRegion(
                    label=label,
                    base_address=base_address,
                    size=size,
                    resource_type=resource_type,
                    resource_attribute=resource_attribute,
                    memory_type=memory_type,
                    cache_attributes=cache_attributes
                ))
        return regions
    except Exception as e:
        print(f"Error parsing preloader: {str(e)}")
        return []
"""

# Check for memory region overlaps
def check_memory_region_overlap(regions: List[MemoryRegion], new_region: MemoryRegion) -> bool:
    """
    Checks if the new region overlaps with existing regions.
    Returns True if an overlap is detected, False otherwise.
    """
    for region in regions:
        if region.size == 0:  # Skip terminator
            continue
        existing_end = region.base_address + region.size
        new_end = new_region.base_address + new_region.size
        if (new_region.base_address < existing_end) and (region.base_address < new_end):
            print(f"Error: Overlap detected with region {region.label}")
            return True
    return False

# Generate memory map from preloader data
def generate_memory_map() -> Optional[List[MemoryRegion]]:
    """
    Generates a memory map by parsing the preloader and validating regions.
    Returns a list of MemoryRegion objects or None if generation fails.
    """
    try:
        # Step 1: Parse preloader to extract memory regions
        preloader_regions = parse_preloader_memory_regions()
        if not preloader_regions:
            print("Error: No regions extracted from preloader")
            return None

        # Step 2: Validate and build memory map
        memory_map = []
        for region in preloader_regions:
            # Validate region
            if not region.label or region.size <= 0:
                print(f"Error: Invalid region: {region.label}, size: {region.size}")
                return None

            # Check for overlaps
            if check_memory_region_overlap(memory_map, region):
                print(f"Error: Region {region.label} overlaps with existing regions")
                return None

            # Add region to memory map
            memory_map.append(region)

        # Step 3: Add terminator (for UEFI compatibility)
        memory_map.append(MemoryRegion(
            label="Terminator",
            base_address=0,
            size=0
        ))

        return memory_map

    except Exception as e:
        print(f"Error generating memory map: {str(e)}")
        return None

# Export memory map to JSON (optional)
def export_memory_map_to_json(memory_map: List[MemoryRegion], filename: str = "memory_map.json"):
    """
    Exports the memory map to a JSON file for integration with other systems.
    """
    try:
        with open(filename, "w") as f:
            json.dump([region.to_dict() for region in memory_map], f, indent=2)
        print(f"Memory map exported to {filename}")
    except Exception as e:
        print(f"Error exporting memory map to JSON: {str(e)}")

# Main function to get the platform memory map
def get_platform_memory_map() -> Optional[List[MemoryRegion]]:
    """
    Main entry point to generate and return the platform memory map.
    """
    memory_map = generate_memory_map()
    if memory_map is None:
        print("Failed to generate memory map")
        return None
    
    # Print the generated memory map for debugging
    print("Generated Memory Map:")
    for region in memory_map:
        print(f"Label: {region.label}, Base: 0x{region.base_address:08X}, Size: 0x{region.size:08X}, "
              f"Type: {region.resource_type}, Attr: {region.resource_attribute}, "
              f"MemType: {region.memory_type}, Cache: {region.cache_attributes}")
    
    # Optionally export to JSON
    export_memory_map_to_json(memory_map)
    
    return memory_map

# Example usage
if __name__ == "__main__":
    memory_map = get_platform_memory_map()
    if memory_map:
        print("Memory map generated successfully!")
    else:
        print("Failed to generate memory map")
