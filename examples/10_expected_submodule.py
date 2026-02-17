#!/usr/bin/env python3
"""Build ExpectedSubmoduleBlockReq for device configuration."""

from profinet import ExpectedSubmoduleBlockReq

# Build expected configuration
builder = ExpectedSubmoduleBlockReq()

# Add DAP (Device Access Point)
builder.add_submodule(
    api=0,
    slot=0,
    subslot=0x0001,  # DAP
    module_ident=0x00000001,
    submodule_ident=0x00000001,
    submodule_type=0,  # NO_IO
)

# Add interface submodule
builder.add_submodule(
    api=0,
    slot=0,
    subslot=0x8000,  # Interface
    module_ident=0x00000001,
    submodule_ident=0x00008000,
    submodule_type=0,  # NO_IO
)

# Add port submodules
for port_num in range(1, 3):
    builder.add_submodule(
        api=0,
        slot=0,
        subslot=0x8000 + port_num,  # Port 1, 2
        module_ident=0x00000001,
        submodule_ident=0x00008000 + port_num,
        submodule_type=0,  # NO_IO
    )

# Add I/O module with input data
builder.add_submodule(
    api=0,
    slot=1,
    subslot=0x0001,
    module_ident=0x00001234,
    submodule_ident=0x00005678,
    submodule_type=1,  # INPUT
    input_length=16,
)

# Build the block
block_data = builder.to_bytes()
print(f"ExpectedSubmoduleBlockReq: {len(block_data)} bytes")
print(f"APIs: {len(builder.apis)}")
for api in builder.apis:
    print(f"  API {api.api}, Slot {api.slot_number}:")
    for sub in api.submodules:
        print(f"    Subslot 0x{sub.subslot_number:04X}, Type {sub.submodule_type}")
