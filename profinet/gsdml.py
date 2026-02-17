"""GSDML (Generic Station Description Markup Language) parser for PROFINET devices.

Parses GSDML XML files to extract module catalogs and build IOSlot lists
for cyclic IO configuration, eliminating manual hardcoding of device-specific
module/submodule IDs and IO data sizes.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET  # nosec B405 — GSDML files are local trusted vendor data
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

from .rpc import IOSlot

# GSDML data type -> byte size. None means Length attribute is required.
GSDML_TYPE_SIZES: Dict[str, Optional[int]] = {
    "Boolean": 1,
    "Integer8": 1,
    "Integer16": 2,
    "Integer32": 4,
    "Integer64": 8,
    "Unsigned8": 1,
    "Unsigned16": 2,
    "Unsigned32": 4,
    "Unsigned64": 8,
    "Float32": 4,
    "Float64": 8,
    "TimeStamp": 8,
    # Variable-length types require Length attribute
    "OctetString": None,
    "VisibleString": None,
}


def _find(elem: ET.Element, local_name: str) -> Optional[ET.Element]:
    """Find first direct child by local name, ignoring XML namespace."""
    return elem.find(f"{{*}}{local_name}")


def _findall(elem: ET.Element, local_name: str) -> List[ET.Element]:
    """Find all direct children by local name, ignoring XML namespace."""
    return elem.findall(f"{{*}}{local_name}")


def _find_deep(elem: ET.Element, local_name: str) -> Optional[ET.Element]:
    """Find first descendant by local name, ignoring XML namespace."""
    return elem.find(f".//{{*}}{local_name}")


def _findall_deep(elem: ET.Element, local_name: str) -> List[ET.Element]:
    """Find all descendants by local name, ignoring XML namespace."""
    return elem.findall(f".//{{*}}{local_name}")


def _parse_int(value: Optional[str]) -> int:
    """Parse integer from string, supporting 0x hex prefix."""
    if value is None:
        return 0
    value = value.strip()
    if value.startswith(("0x", "0X")):
        return int(value, 16)
    return int(value)


def _parse_io_data_size(submodule_elem: ET.Element, direction: str) -> int:
    """Parse total IO data size in bytes for a direction from a submodule element.

    Args:
        submodule_elem: A VirtualSubmoduleItem element.
        direction: 'Input' or 'Output'.

    Returns:
        Total byte size for the given direction.
    """
    io_data = _find(submodule_elem, "IOData")
    if io_data is None:
        return 0
    dir_elem = _find(io_data, direction)
    if dir_elem is None:
        return 0
    total = 0
    for data_item in _findall(dir_elem, "DataItem"):
        data_type = data_item.get("DataType", "")
        length_attr = data_item.get("Length")
        if length_attr is not None:
            total += int(length_attr)
        else:
            size = GSDML_TYPE_SIZES.get(data_type)
            if size is not None:
                total += size
    return total


def _parse_slot_spec(spec: Optional[str]) -> List[int]:
    """Parse GSDML slot spec like '1..3' or '1 2 5' into list of ints."""
    if not spec:
        return []
    result: List[int] = []
    for part in spec.replace(",", " ").split():
        if ".." in part:
            start_s, end_s = part.split("..", 1)
            result.extend(range(int(start_s), int(end_s) + 1))
        else:
            result.append(int(part))
    return result


@dataclass
class GSDMLSubmodule:
    """A GSDML virtual submodule definition."""

    id: str
    submodule_ident: int
    input_length: int = 0
    output_length: int = 0


@dataclass
class GSDMLModule:
    """A GSDML module definition from ModuleList."""

    id: str
    module_ident: int
    submodules: List[GSDMLSubmodule] = field(default_factory=list)
    # UseableSubmodules: references to top-level SubmoduleList entries
    useable_submodules: Dict[str, str] = field(default_factory=dict)
    fixed_subslots: Dict[str, List[int]] = field(default_factory=dict)
    allowed_subslots: Dict[str, List[int]] = field(default_factory=dict)


@dataclass
class GSDMLSystemSubmodule:
    """A system-defined submodule (interface/port)."""

    subslot_number: int
    submodule_ident: int


@dataclass
class GSDMLDAP:
    """Device Access Point configuration."""

    id: str
    module_ident: int
    submodules: List[GSDMLSubmodule] = field(default_factory=list)
    system_submodules: List[GSDMLSystemSubmodule] = field(default_factory=list)
    useable_modules: Dict[str, str] = field(default_factory=dict)
    fixed_slots: Dict[str, List[int]] = field(default_factory=dict)
    allowed_slots: Dict[str, List[int]] = field(default_factory=dict)


@dataclass
class GSDMLDevice:
    """Parsed GSDML device description with module catalog."""

    vendor_id: int = 0
    device_id: int = 0
    daps: List[GSDMLDAP] = field(default_factory=list)
    modules: Dict[str, GSDMLModule] = field(default_factory=dict)
    # Top-level SubmoduleList entries (referenced by UseableSubmodules)
    submodule_catalog: Dict[str, GSDMLSubmodule] = field(default_factory=dict)

    def get_dap(self, dap_id: Optional[str] = None) -> GSDMLDAP:
        """Get DAP by ID, or first DAP if dap_id is None."""
        if not self.daps:
            raise ValueError("No DAP found in GSDML")
        if dap_id is None:
            return self.daps[0]
        for dap in self.daps:
            if dap.id == dap_id:
                return dap
        raise ValueError(f"DAP '{dap_id}' not found")

    def build_io_slots(
        self,
        slot_assignment: Optional[Dict[int, str]] = None,
        submodule_assignment: Optional[Dict[int, Dict[int, str]]] = None,
        dap_id: Optional[str] = None,
    ) -> List[IOSlot]:
        """Build IOSlot list from GSDML module catalog.

        Args:
            slot_assignment: Explicit mapping of slot_number -> module_id.
                If None, uses FixedInSlots from UseableModules.
            submodule_assignment: For modules using UseableSubmodules,
                mapping of slot_number -> {subslot_number -> submodule_id}.
                FixedInSubslots are always included automatically.
            dap_id: DAP to use. If None, uses first DAP.

        Returns:
            List of IOSlot for cyclic IO setup.
        """
        dap = self.get_dap(dap_id)
        slots: List[IOSlot] = []

        # DAP virtual submodules at slot 0
        for i, sub in enumerate(dap.submodules):
            slots.append(
                IOSlot(
                    slot=0,
                    subslot=i + 1,
                    input_length=sub.input_length,
                    output_length=sub.output_length,
                    module_ident=dap.module_ident,
                    submodule_ident=sub.submodule_ident,
                )
            )

        # System submodules (interface/ports) at slot 0
        for sys_sub in dap.system_submodules:
            slots.append(
                IOSlot(
                    slot=0,
                    subslot=sys_sub.subslot_number,
                    module_ident=dap.module_ident,
                    submodule_ident=sys_sub.submodule_ident,
                )
            )

        # Determine slot assignment
        if slot_assignment is None:
            assignment: Dict[int, str] = {}
            for mod_id, fixed in dap.fixed_slots.items():
                for slot_num in fixed:
                    assignment[slot_num] = mod_id
        else:
            assignment = slot_assignment

        sub_assign = submodule_assignment or {}

        # Add module slots
        for slot_num in sorted(assignment):
            mod_id = assignment[slot_num]
            mod = self.modules.get(mod_id)
            if mod is None:
                continue

            if mod.submodules:
                # Module has inline VirtualSubmoduleList
                for i, sub in enumerate(mod.submodules):
                    slots.append(
                        IOSlot(
                            slot=slot_num,
                            subslot=i + 1,
                            input_length=sub.input_length,
                            output_length=sub.output_length,
                            module_ident=mod.module_ident,
                            submodule_ident=sub.submodule_ident,
                        )
                    )
            elif mod.useable_submodules:
                # Module uses UseableSubmodules referencing submodule_catalog
                self._add_useable_submodule_slots(
                    slots, mod, slot_num, sub_assign.get(slot_num, {})
                )

        return slots

    def _add_useable_submodule_slots(
        self,
        slots: List[IOSlot],
        mod: GSDMLModule,
        slot_num: int,
        subslot_assign: Dict[int, str],
    ) -> None:
        """Resolve UseableSubmodules for a module and add IOSlots."""
        # Collect subslot -> submodule_id assignments
        resolved: Dict[int, str] = {}

        # FixedInSubslots are always included
        for sub_id, subslot_list in mod.fixed_subslots.items():
            for subslot_num in subslot_list:
                resolved[subslot_num] = sub_id

        # User-provided subslot assignments
        for subslot_num, sub_id in subslot_assign.items():
            resolved[subslot_num] = sub_id

        for subslot_num in sorted(resolved):
            sub_id = resolved[subslot_num]
            cat_sub = self.submodule_catalog.get(sub_id)
            if cat_sub is None:
                continue
            slots.append(
                IOSlot(
                    slot=slot_num,
                    subslot=subslot_num,
                    input_length=cat_sub.input_length,
                    output_length=cat_sub.output_length,
                    module_ident=mod.module_ident,
                    submodule_ident=cat_sub.submodule_ident,
                )
            )

    def build_io_slots_from_device(
        self,
        device_slots: list,
        dap_id: Optional[str] = None,
    ) -> List[IOSlot]:
        """Build IOSlot list by matching runtime slot discovery against GSDML.

        Args:
            device_slots: List of SlotInfo from discover_slots().
            dap_id: DAP to use. If None, uses first DAP.

        Returns:
            List of IOSlot with IO sizes filled from GSDML catalog.
        """
        dap = self.get_dap(dap_id)

        # Build lookup: module_ident -> {submodule_ident -> (input_len, output_len)}
        ident_lookup: Dict[int, Dict[int, tuple]] = {}

        # DAP submodules
        for sub in dap.submodules:
            ident_lookup.setdefault(dap.module_ident, {})[sub.submodule_ident] = (
                sub.input_length,
                sub.output_length,
            )

        # System submodules (no IO data)
        for sys_sub in dap.system_submodules:
            ident_lookup.setdefault(dap.module_ident, {})[sys_sub.submodule_ident] = (0, 0)

        # All catalog modules (inline submodules)
        for mod in self.modules.values():
            for sub in mod.submodules:
                ident_lookup.setdefault(mod.module_ident, {})[sub.submodule_ident] = (
                    sub.input_length,
                    sub.output_length,
                )
            # Modules with UseableSubmodules: register catalog entries under module_ident
            if mod.useable_submodules:
                for sub_id in mod.useable_submodules:
                    cat_sub = self.submodule_catalog.get(sub_id)
                    if cat_sub is not None:
                        ident_lookup.setdefault(mod.module_ident, {})[cat_sub.submodule_ident] = (
                            cat_sub.input_length,
                            cat_sub.output_length,
                        )

        slots: List[IOSlot] = []
        for ds in device_slots:
            input_len = 0
            output_len = 0
            mod_subs = ident_lookup.get(ds.module_ident, {})
            if ds.submodule_ident in mod_subs:
                input_len, output_len = mod_subs[ds.submodule_ident]
            slots.append(
                IOSlot(
                    slot=ds.slot,
                    subslot=ds.subslot,
                    input_length=input_len,
                    output_length=output_len,
                    module_ident=ds.module_ident,
                    submodule_ident=ds.submodule_ident,
                )
            )

        return slots


def _parse_submodule(elem: ET.Element) -> GSDMLSubmodule:
    """Parse a VirtualSubmoduleItem element."""
    return GSDMLSubmodule(
        id=elem.get("ID", ""),
        submodule_ident=_parse_int(elem.get("SubmoduleIdentNumber")),
        input_length=_parse_io_data_size(elem, "Input"),
        output_length=_parse_io_data_size(elem, "Output"),
    )


def _parse_virtual_submodules(parent: ET.Element) -> List[GSDMLSubmodule]:
    """Parse VirtualSubmoduleList from a parent element."""
    vsl = _find(parent, "VirtualSubmoduleList")
    if vsl is None:
        return []
    return [_parse_submodule(vs) for vs in _findall(vsl, "VirtualSubmoduleItem")]


def _parse_system_submodules(dap_elem: ET.Element) -> List[GSDMLSystemSubmodule]:
    """Parse SystemDefinedSubmoduleList from a DAP element."""
    sdsl = _find(dap_elem, "SystemDefinedSubmoduleList")
    if sdsl is None:
        return []
    result: List[GSDMLSystemSubmodule] = []
    for tag in ("InterfaceSubmoduleItem", "PortSubmoduleItem"):
        for item in _findall(sdsl, tag):
            result.append(
                GSDMLSystemSubmodule(
                    subslot_number=_parse_int(item.get("SubslotNumber")),
                    submodule_ident=_parse_int(item.get("SubmoduleIdentNumber")),
                )
            )
    return result


def _parse_useable_modules(
    dap_elem: ET.Element,
) -> tuple:
    """Parse UseableModules from a DAP element.

    Returns:
        (useable_modules, fixed_slots, allowed_slots) dicts.
    """
    um = _find(dap_elem, "UseableModules")
    if um is None:
        return {}, {}, {}
    useable: Dict[str, str] = {}
    fixed: Dict[str, List[int]] = {}
    allowed: Dict[str, List[int]] = {}
    for ref in _findall(um, "ModuleItemRef"):
        target = ref.get("ModuleItemTarget", "")
        useable[target] = target
        fixed_spec = ref.get("FixedInSlots")
        if fixed_spec:
            fixed[target] = _parse_slot_spec(fixed_spec)
        allowed_spec = ref.get("AllowedInSlots")
        if allowed_spec:
            allowed[target] = _parse_slot_spec(allowed_spec)
    return useable, fixed, allowed


def _parse_useable_submodules(
    mod_elem: ET.Element,
) -> tuple:
    """Parse UseableSubmodules from a ModuleItem element.

    Returns:
        (useable_submodules, fixed_subslots, allowed_subslots) dicts.
    """
    us = _find(mod_elem, "UseableSubmodules")
    if us is None:
        return {}, {}, {}
    useable: Dict[str, str] = {}
    fixed: Dict[str, List[int]] = {}
    allowed: Dict[str, List[int]] = {}
    for ref in _findall(us, "SubmoduleItemRef"):
        target = ref.get("SubmoduleItemTarget", "")
        useable[target] = target
        fixed_spec = ref.get("FixedInSubslots")
        if fixed_spec:
            fixed[target] = _parse_slot_spec(fixed_spec)
        allowed_spec = ref.get("AllowedInSubslots")
        if allowed_spec:
            allowed[target] = _parse_slot_spec(allowed_spec)
    return useable, fixed, allowed


def _parse_gsdml_root(root: ET.Element) -> GSDMLDevice:
    """Parse a GSDML XML root element into a GSDMLDevice."""
    device = GSDMLDevice()

    # DeviceIdentity
    dev_ident = _find_deep(root, "DeviceIdentity")
    if dev_ident is not None:
        device.vendor_id = _parse_int(dev_ident.get("VendorID"))
        device.device_id = _parse_int(dev_ident.get("DeviceID"))

    # Top-level SubmoduleList (referenced by UseableSubmodules)
    for sub_elem in _findall_deep(root, "SubmoduleItem"):
        sub = _parse_submodule(sub_elem)
        device.submodule_catalog[sub.id] = sub

    # DeviceAccessPointList
    for dap_elem in _findall_deep(root, "DeviceAccessPointItem"):
        useable, fixed, allowed = _parse_useable_modules(dap_elem)
        dap = GSDMLDAP(
            id=dap_elem.get("ID", ""),
            module_ident=_parse_int(dap_elem.get("ModuleIdentNumber")),
            submodules=_parse_virtual_submodules(dap_elem),
            system_submodules=_parse_system_submodules(dap_elem),
            useable_modules=useable,
            fixed_slots=fixed,
            allowed_slots=allowed,
        )
        device.daps.append(dap)

    # ModuleList
    for mod_elem in _findall_deep(root, "ModuleItem"):
        useable_subs, fixed_subs, allowed_subs = _parse_useable_submodules(mod_elem)
        mod = GSDMLModule(
            id=mod_elem.get("ID", ""),
            module_ident=_parse_int(mod_elem.get("ModuleIdentNumber")),
            submodules=_parse_virtual_submodules(mod_elem),
            useable_submodules=useable_subs,
            fixed_subslots=fixed_subs,
            allowed_subslots=allowed_subs,
        )
        device.modules[mod.id] = mod

    return device


def load_gsdml(path: Union[str, Path]) -> GSDMLDevice:
    """Parse a GSDML XML file into a GSDMLDevice.

    Args:
        path: Path to GSDML XML file.

    Returns:
        GSDMLDevice with full module catalog.
    """
    tree = ET.parse(str(path))  # nosec B314 — GSDML files are local trusted vendor data
    return _parse_gsdml_root(tree.getroot())


def parse_gsdml(
    path: Union[str, Path],
    slot_assignment: Optional[Dict[int, str]] = None,
) -> List[IOSlot]:
    """Parse GSDML file and build IOSlot list.

    Shortcut combining load_gsdml() and build_io_slots().

    Args:
        path: Path to GSDML XML file.
        slot_assignment: Optional explicit slot_number -> module_id mapping.
            If None, uses FixedInSlots from the GSDML.

    Returns:
        List of IOSlot ready for IOCRSetup.
    """
    device = load_gsdml(path)
    return device.build_io_slots(slot_assignment=slot_assignment)
