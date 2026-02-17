"""Tests for GSDML parser."""

import xml.etree.ElementTree as ET
from dataclasses import dataclass

import pytest

from profinet.gsdml import (
    GSDMLDevice,
    _parse_gsdml_root,
    _parse_io_data_size,
    _parse_slot_spec,
)
from profinet.rpc import IOSlot

# ---------------------------------------------------------------------------
# Minimal GSDML fixture (no namespace)
# ---------------------------------------------------------------------------
MINIMAL_GSDML = """\
<ISO15745Profile>
  <ProfileBody>
    <DeviceIdentity VendorID="0x002A" DeviceID="0x0003"/>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP_1" ModuleIdentNumber="0x00000001">
          <SystemDefinedSubmoduleList>
            <InterfaceSubmoduleItem SubslotNumber="0x8000"
                                    SubmoduleIdentNumber="0x00000100"/>
            <PortSubmoduleItem SubslotNumber="0x8001"
                               SubmoduleIdentNumber="0x00000200"/>
          </SystemDefinedSubmoduleList>
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="DAP_Sub" SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Input>
                  <DataItem DataType="Unsigned8"/>
                </Input>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
          <UseableModules>
            <ModuleItemRef ModuleItemTarget="MOD_INPUT"
                           AllowedInSlots="1..3" FixedInSlots="1"/>
            <ModuleItemRef ModuleItemTarget="MOD_OUTPUT"
                           AllowedInSlots="1..3" FixedInSlots="2"/>
          </UseableModules>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="MOD_INPUT" ModuleIdentNumber="0x00000010">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="MOD_IN_Sub"
                                  SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Input>
                  <DataItem DataType="OctetString" Length="4"/>
                </Input>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
        <ModuleItem ID="MOD_OUTPUT" ModuleIdentNumber="0x00000020">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="MOD_OUT_Sub"
                                  SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Output>
                  <DataItem DataType="Unsigned16"/>
                </Output>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
      </ModuleList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""


def _device_from_xml(xml_str: str) -> GSDMLDevice:
    """Helper: parse inline XML string into GSDMLDevice."""
    return _parse_gsdml_root(ET.fromstring(xml_str))


# ---------------------------------------------------------------------------
# TestParseIODataSize
# ---------------------------------------------------------------------------
class TestParseIODataSize:
    """Test IO data size extraction from DataItem elements."""

    def _size(self, xml_snippet: str, direction: str) -> int:
        elem = ET.fromstring(xml_snippet)
        return _parse_io_data_size(elem, direction)

    def test_unsigned8(self):
        xml = '<Sub><IOData><Input><DataItem DataType="Unsigned8"/></Input></IOData></Sub>'
        assert self._size(xml, "Input") == 1

    def test_unsigned16(self):
        xml = '<Sub><IOData><Input><DataItem DataType="Unsigned16"/></Input></IOData></Sub>'
        assert self._size(xml, "Input") == 2

    def test_unsigned32(self):
        xml = '<Sub><IOData><Output><DataItem DataType="Unsigned32"/></Output></IOData></Sub>'
        assert self._size(xml, "Output") == 4

    def test_float32(self):
        xml = '<Sub><IOData><Input><DataItem DataType="Float32"/></Input></IOData></Sub>'
        assert self._size(xml, "Input") == 4

    def test_float64(self):
        xml = '<Sub><IOData><Input><DataItem DataType="Float64"/></Input></IOData></Sub>'
        assert self._size(xml, "Input") == 8

    def test_integer16(self):
        xml = '<Sub><IOData><Input><DataItem DataType="Integer16"/></Input></IOData></Sub>'
        assert self._size(xml, "Input") == 2

    def test_octet_string_with_length(self):
        xml = '<Sub><IOData><Input><DataItem DataType="OctetString" Length="10"/></Input></IOData></Sub>'
        assert self._size(xml, "Input") == 10

    def test_visible_string_with_length(self):
        xml = '<Sub><IOData><Output><DataItem DataType="VisibleString" Length="32"/></Output></IOData></Sub>'
        assert self._size(xml, "Output") == 32

    def test_explicit_length_overrides_type(self):
        """When Length attr is present, it should be used even for fixed-size types."""
        xml = (
            '<Sub><IOData><Input><DataItem DataType="Unsigned8" Length="3"/></Input></IOData></Sub>'
        )
        assert self._size(xml, "Input") == 3

    def test_multiple_data_items(self):
        xml = """<Sub><IOData><Input>
            <DataItem DataType="Unsigned16"/>
            <DataItem DataType="Unsigned8"/>
            <DataItem DataType="OctetString" Length="5"/>
        </Input></IOData></Sub>"""
        assert self._size(xml, "Input") == 2 + 1 + 5

    def test_missing_direction_returns_zero(self):
        xml = '<Sub><IOData><Input><DataItem DataType="Unsigned8"/></Input></IOData></Sub>'
        assert self._size(xml, "Output") == 0

    def test_no_io_data_returns_zero(self):
        xml = "<Sub></Sub>"
        assert self._size(xml, "Input") == 0

    def test_empty_direction_returns_zero(self):
        xml = "<Sub><IOData><Input></Input></IOData></Sub>"
        assert self._size(xml, "Input") == 0

    def test_unknown_type_no_length_ignored(self):
        xml = '<Sub><IOData><Input><DataItem DataType="SomeCustomType"/></Input></IOData></Sub>'
        assert self._size(xml, "Input") == 0

    def test_boolean(self):
        xml = '<Sub><IOData><Input><DataItem DataType="Boolean"/></Input></IOData></Sub>'
        assert self._size(xml, "Input") == 1

    def test_timestamp(self):
        xml = '<Sub><IOData><Input><DataItem DataType="TimeStamp"/></Input></IOData></Sub>'
        assert self._size(xml, "Input") == 8


# ---------------------------------------------------------------------------
# TestLoadGsdml
# ---------------------------------------------------------------------------
class TestLoadGsdml:
    """Test loading a minimal GSDML into GSDMLDevice."""

    def test_vendor_and_device_id(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        assert dev.vendor_id == 0x002A
        assert dev.device_id == 0x0003

    def test_dap_count(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        assert len(dev.daps) == 1

    def test_dap_id_and_module_ident(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        dap = dev.daps[0]
        assert dap.id == "DAP_1"
        assert dap.module_ident == 0x00000001

    def test_dap_virtual_submodule(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        dap = dev.daps[0]
        assert len(dap.submodules) == 1
        sub = dap.submodules[0]
        assert sub.id == "DAP_Sub"
        assert sub.submodule_ident == 0x00000001
        assert sub.input_length == 1  # Unsigned8
        assert sub.output_length == 0

    def test_dap_system_submodules(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        dap = dev.daps[0]
        assert len(dap.system_submodules) == 2
        iface = dap.system_submodules[0]
        assert iface.subslot_number == 0x8000
        assert iface.submodule_ident == 0x00000100
        port = dap.system_submodules[1]
        assert port.subslot_number == 0x8001
        assert port.submodule_ident == 0x00000200

    def test_useable_modules(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        dap = dev.daps[0]
        assert "MOD_INPUT" in dap.useable_modules
        assert "MOD_OUTPUT" in dap.useable_modules

    def test_fixed_slots(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        dap = dev.daps[0]
        assert dap.fixed_slots["MOD_INPUT"] == [1]
        assert dap.fixed_slots["MOD_OUTPUT"] == [2]

    def test_allowed_slots(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        dap = dev.daps[0]
        assert dap.allowed_slots["MOD_INPUT"] == [1, 2, 3]
        assert dap.allowed_slots["MOD_OUTPUT"] == [1, 2, 3]

    def test_module_count(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        assert len(dev.modules) == 2

    def test_module_input(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        mod = dev.modules["MOD_INPUT"]
        assert mod.module_ident == 0x00000010
        assert len(mod.submodules) == 1
        assert mod.submodules[0].input_length == 4
        assert mod.submodules[0].output_length == 0

    def test_module_output(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        mod = dev.modules["MOD_OUTPUT"]
        assert mod.module_ident == 0x00000020
        assert len(mod.submodules) == 1
        assert mod.submodules[0].input_length == 0
        assert mod.submodules[0].output_length == 2  # Unsigned16

    def test_get_dap_default(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        dap = dev.get_dap()
        assert dap.id == "DAP_1"

    def test_get_dap_by_id(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        dap = dev.get_dap("DAP_1")
        assert dap.id == "DAP_1"

    def test_get_dap_not_found(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        with pytest.raises(ValueError, match="not found"):
            dev.get_dap("NONEXISTENT")


# ---------------------------------------------------------------------------
# TestBuildIOSlots
# ---------------------------------------------------------------------------
class TestBuildIOSlots:
    """Test building IOSlot lists from GSDML."""

    def test_fixed_in_slots_auto(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots()
        # Slot 0: DAP sub (subslot 1) + interface (0x8000) + port (0x8001)
        # Slot 1: MOD_INPUT sub (subslot 1)
        # Slot 2: MOD_OUTPUT sub (subslot 1)
        assert len(slots) == 5

    def test_dap_always_slot_zero(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots()
        dap_slots = [s for s in slots if s.slot == 0]
        assert len(dap_slots) == 3  # 1 virtual + 2 system

    def test_dap_subslot_one(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots()
        dap_sub = [s for s in slots if s.slot == 0 and s.subslot == 1][0]
        assert dap_sub.input_length == 1
        assert dap_sub.output_length == 0
        assert dap_sub.module_ident == 0x00000001

    def test_system_submodule_slots(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots()
        iface = [s for s in slots if s.subslot == 0x8000][0]
        assert iface.slot == 0
        assert iface.module_ident == 0x00000001
        assert iface.submodule_ident == 0x00000100
        port = [s for s in slots if s.subslot == 0x8001][0]
        assert port.slot == 0
        assert port.submodule_ident == 0x00000200

    def test_module_slot_1_input(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots()
        mod_in = [s for s in slots if s.slot == 1][0]
        assert mod_in.subslot == 1
        assert mod_in.input_length == 4
        assert mod_in.output_length == 0
        assert mod_in.module_ident == 0x00000010

    def test_module_slot_2_output(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots()
        mod_out = [s for s in slots if s.slot == 2][0]
        assert mod_out.subslot == 1
        assert mod_out.input_length == 0
        assert mod_out.output_length == 2
        assert mod_out.module_ident == 0x00000020

    def test_explicit_slot_assignment(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots(slot_assignment={3: "MOD_OUTPUT", 5: "MOD_INPUT"})
        mod_slots = [s for s in slots if s.slot > 0]
        assert len(mod_slots) == 2
        assert mod_slots[0].slot == 3
        assert mod_slots[0].output_length == 2
        assert mod_slots[1].slot == 5
        assert mod_slots[1].input_length == 4

    def test_explicit_assignment_unknown_module_skipped(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots(slot_assignment={1: "NONEXISTENT"})
        # Only DAP slots, no module slots
        assert all(s.slot == 0 for s in slots)

    def test_slot_order(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots()
        slot_nums = [s.slot for s in slots]
        # DAP (0,0,0) then modules (1, 2)
        assert slot_nums == [0, 0, 0, 1, 2]


# ---------------------------------------------------------------------------
# TestBuildIOSlotsFromDevice
# ---------------------------------------------------------------------------
class TestBuildIOSlotsFromDevice:
    """Test runtime matching of device slots against GSDML."""

    @dataclass
    class FakeSlotInfo:
        slot: int
        subslot: int
        module_ident: int = 0
        submodule_ident: int = 0

    def test_matching_fills_io_sizes(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        device_slots = [
            self.FakeSlotInfo(
                slot=0, subslot=1, module_ident=0x00000001, submodule_ident=0x00000001
            ),
            self.FakeSlotInfo(
                slot=1, subslot=1, module_ident=0x00000010, submodule_ident=0x00000001
            ),
        ]
        slots = dev.build_io_slots_from_device(device_slots)
        assert len(slots) == 2
        assert slots[0].input_length == 1  # DAP Unsigned8
        assert slots[1].input_length == 4  # MOD_INPUT OctetString(4)

    def test_unknown_module_gets_zero(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        device_slots = [
            self.FakeSlotInfo(
                slot=1, subslot=1, module_ident=0xDEADBEEF, submodule_ident=0x00000001
            ),
        ]
        slots = dev.build_io_slots_from_device(device_slots)
        assert slots[0].input_length == 0
        assert slots[0].output_length == 0

    def test_preserves_slot_subslot(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        device_slots = [
            self.FakeSlotInfo(
                slot=7, subslot=3, module_ident=0x00000020, submodule_ident=0x00000001
            ),
        ]
        slots = dev.build_io_slots_from_device(device_slots)
        assert slots[0].slot == 7
        assert slots[0].subslot == 3
        assert slots[0].output_length == 2

    def test_system_submodule_matching(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        device_slots = [
            self.FakeSlotInfo(
                slot=0,
                subslot=0x8000,
                module_ident=0x00000001,
                submodule_ident=0x00000100,
            ),
        ]
        slots = dev.build_io_slots_from_device(device_slots)
        assert slots[0].input_length == 0
        assert slots[0].output_length == 0

    def test_empty_device_slots(self):
        dev = _device_from_xml(MINIMAL_GSDML)
        slots = dev.build_io_slots_from_device([])
        assert slots == []


# ---------------------------------------------------------------------------
# TestNamespaceHandling
# ---------------------------------------------------------------------------
class TestNamespaceHandling:
    """Test that namespaced GSDML XML still parses correctly."""

    NAMESPACED_GSDML = """\
<ISO15745Profile xmlns="http://www.profibus.com/GSDML/2.4">
  <ProfileBody>
    <DeviceIdentity VendorID="0x0042" DeviceID="0x0007"/>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP_NS" ModuleIdentNumber="0x00000002">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="Sub1" SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Input>
                  <DataItem DataType="Unsigned32"/>
                </Input>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="MOD_A" ModuleIdentNumber="0x000000AA">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="MOD_A_Sub" SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Output>
                  <DataItem DataType="Float32"/>
                </Output>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
      </ModuleList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""

    def test_vendor_id_with_namespace(self):
        dev = _device_from_xml(self.NAMESPACED_GSDML)
        assert dev.vendor_id == 0x0042

    def test_device_id_with_namespace(self):
        dev = _device_from_xml(self.NAMESPACED_GSDML)
        assert dev.device_id == 0x0007

    def test_dap_parsed_with_namespace(self):
        dev = _device_from_xml(self.NAMESPACED_GSDML)
        assert len(dev.daps) == 1
        assert dev.daps[0].id == "DAP_NS"
        assert dev.daps[0].module_ident == 0x00000002

    def test_submodule_io_with_namespace(self):
        dev = _device_from_xml(self.NAMESPACED_GSDML)
        assert dev.daps[0].submodules[0].input_length == 4  # Unsigned32

    def test_module_with_namespace(self):
        dev = _device_from_xml(self.NAMESPACED_GSDML)
        mod = dev.modules["MOD_A"]
        assert mod.module_ident == 0x000000AA
        assert mod.submodules[0].output_length == 4  # Float32

    def test_different_namespace_version(self):
        xml = self.NAMESPACED_GSDML.replace("GSDML/2.4", "GSDML/2.3")
        dev = _device_from_xml(xml)
        assert dev.vendor_id == 0x0042
        assert len(dev.daps) == 1


# ---------------------------------------------------------------------------
# TestEdgeCases
# ---------------------------------------------------------------------------
class TestEdgeCases:
    """Test edge cases and unusual GSDML structures."""

    def test_no_io_data_module(self):
        """Module with VirtualSubmoduleItem but no IOData."""
        xml = """\
<ISO15745Profile>
  <ProfileBody>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001">
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="NO_IO" ModuleIdentNumber="0x00000099">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="S1" SubmoduleIdentNumber="0x00000001">
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
      </ModuleList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""
        dev = _device_from_xml(xml)
        mod = dev.modules["NO_IO"]
        assert mod.submodules[0].input_length == 0
        assert mod.submodules[0].output_length == 0

    def test_no_virtual_submodule_list(self):
        """Module with no VirtualSubmoduleList at all."""
        xml = """\
<ISO15745Profile>
  <ProfileBody>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001">
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="EMPTY" ModuleIdentNumber="0x000000FF">
        </ModuleItem>
      </ModuleList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""
        dev = _device_from_xml(xml)
        mod = dev.modules["EMPTY"]
        assert mod.submodules == []

    def test_multiple_daps(self):
        xml = """\
<ISO15745Profile>
  <ProfileBody>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP_A" ModuleIdentNumber="0x00000001">
        </DeviceAccessPointItem>
        <DeviceAccessPointItem ID="DAP_B" ModuleIdentNumber="0x00000002">
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList/>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""
        dev = _device_from_xml(xml)
        assert len(dev.daps) == 2
        assert dev.get_dap().id == "DAP_A"
        assert dev.get_dap("DAP_B").id == "DAP_B"
        assert dev.get_dap("DAP_B").module_ident == 0x00000002

    def test_no_device_identity(self):
        xml = """\
<ISO15745Profile>
  <ProfileBody>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001">
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList/>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""
        dev = _device_from_xml(xml)
        assert dev.vendor_id == 0
        assert dev.device_id == 0

    def test_no_dap_raises_on_get(self):
        dev = GSDMLDevice()
        with pytest.raises(ValueError, match="No DAP"):
            dev.get_dap()

    def test_no_useable_modules(self):
        """DAP without UseableModules -> build_io_slots returns only DAP slots."""
        xml = """\
<ISO15745Profile>
  <ProfileBody>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="S" SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Input><DataItem DataType="Unsigned8"/></Input>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList/>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""
        dev = _device_from_xml(xml)
        slots = dev.build_io_slots()
        assert len(slots) == 1
        assert slots[0].slot == 0
        assert slots[0].subslot == 1
        assert slots[0].input_length == 1

    def test_module_with_multiple_submodules(self):
        """Module with multiple virtual submodules -> multiple subslots."""
        xml = """\
<ISO15745Profile>
  <ProfileBody>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001">
          <UseableModules>
            <ModuleItemRef ModuleItemTarget="MULTI" FixedInSlots="1"/>
          </UseableModules>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="MULTI" ModuleIdentNumber="0x00000030">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="MS1" SubmoduleIdentNumber="0x00000001">
              <IOData><Input><DataItem DataType="Unsigned16"/></Input></IOData>
            </VirtualSubmoduleItem>
            <VirtualSubmoduleItem ID="MS2" SubmoduleIdentNumber="0x00000002">
              <IOData><Output><DataItem DataType="Unsigned32"/></Output></IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
      </ModuleList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""
        dev = _device_from_xml(xml)
        slots = dev.build_io_slots()
        mod_slots = [s for s in slots if s.slot == 1]
        assert len(mod_slots) == 2
        assert mod_slots[0].subslot == 1
        assert mod_slots[0].input_length == 2
        assert mod_slots[1].subslot == 2
        assert mod_slots[1].output_length == 4

    def test_dap_with_multiple_virtual_submodules(self):
        """DAP with multiple virtual submodules."""
        xml = """\
<ISO15745Profile>
  <ProfileBody>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="DS1" SubmoduleIdentNumber="0x00000001">
              <IOData><Input><DataItem DataType="Unsigned8"/></Input></IOData>
            </VirtualSubmoduleItem>
            <VirtualSubmoduleItem ID="DS2" SubmoduleIdentNumber="0x00000002">
              <IOData><Output><DataItem DataType="Unsigned16"/></Output></IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList/>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""
        dev = _device_from_xml(xml)
        slots = dev.build_io_slots()
        assert len(slots) == 2
        assert slots[0].subslot == 1
        assert slots[0].input_length == 1
        assert slots[1].subslot == 2
        assert slots[1].output_length == 2


# ---------------------------------------------------------------------------
# TestParseSlotSpec
# ---------------------------------------------------------------------------
class TestParseSlotSpec:
    """Test slot spec parsing."""

    def test_single(self):
        assert _parse_slot_spec("1") == [1]

    def test_range(self):
        assert _parse_slot_spec("1..3") == [1, 2, 3]

    def test_space_separated(self):
        assert _parse_slot_spec("1 3 5") == [1, 3, 5]

    def test_mixed(self):
        assert _parse_slot_spec("1..3 5") == [1, 2, 3, 5]

    def test_empty(self):
        assert _parse_slot_spec("") == []

    def test_none(self):
        assert _parse_slot_spec(None) == []

    def test_comma_separated(self):
        assert _parse_slot_spec("1,2,3") == [1, 2, 3]


# ---------------------------------------------------------------------------
# TestLoadGsdmlFile
# ---------------------------------------------------------------------------
class TestLoadGsdmlFile:
    """Test load_gsdml and parse_gsdml with actual file IO."""

    def test_load_gsdml(self, tmp_path):
        from profinet.gsdml import load_gsdml

        gsdml_file = tmp_path / "test.xml"
        gsdml_file.write_text(MINIMAL_GSDML)
        dev = load_gsdml(gsdml_file)
        assert dev.vendor_id == 0x002A
        assert len(dev.daps) == 1
        assert len(dev.modules) == 2

    def test_parse_gsdml(self, tmp_path):
        from profinet.gsdml import parse_gsdml

        gsdml_file = tmp_path / "test.xml"
        gsdml_file.write_text(MINIMAL_GSDML)
        slots = parse_gsdml(gsdml_file)
        assert len(slots) == 5
        assert all(isinstance(s, IOSlot) for s in slots)

    def test_parse_gsdml_with_assignment(self, tmp_path):
        from profinet.gsdml import parse_gsdml

        gsdml_file = tmp_path / "test.xml"
        gsdml_file.write_text(MINIMAL_GSDML)
        slots = parse_gsdml(gsdml_file, slot_assignment={1: "MOD_OUTPUT"})
        mod_slots = [s for s in slots if s.slot > 0]
        assert len(mod_slots) == 1
        assert mod_slots[0].output_length == 2

    def test_load_gsdml_str_path(self, tmp_path):
        from profinet.gsdml import load_gsdml

        gsdml_file = tmp_path / "test.xml"
        gsdml_file.write_text(MINIMAL_GSDML)
        dev = load_gsdml(str(gsdml_file))
        assert dev.vendor_id == 0x002A


# ---------------------------------------------------------------------------
# TestUseableSubmodules
# ---------------------------------------------------------------------------
class TestUseableSubmodules:
    """Test modules that use SubmoduleList + UseableSubmodules pattern."""

    GSDML_WITH_SUBMODULE_LIST = """\
<ISO15745Profile>
  <ProfileBody>
    <DeviceIdentity VendorID="0x02B8" DeviceID="0x07A3"/>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP_1" ModuleIdentNumber="0x00003011">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="DAP" SubmoduleIdentNumber="0x00003010">
              <IOData/>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
          <UseableModules>
            <ModuleItemRef ModuleItemTarget="IDM_DEV" FixedInSlots="1"/>
            <ModuleItemRef ModuleItemTarget="IDM_PWR" FixedInSlots="2"/>
          </UseableModules>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="IDM_DEV" ModuleIdentNumber="0x10000000">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="DEV_S" SubmoduleIdentNumber="0x20000000">
              <IOData>
                <Input><DataItem DataType="Integer16"/></Input>
                <Output><DataItem DataType="Unsigned16"/></Output>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
        <ModuleItem ID="IDM_PWR" ModuleIdentNumber="0x1000032A">
          <UseableSubmodules>
            <SubmoduleItemRef SubmoduleItemTarget="IDS_TOTAL"
                              AllowedInSubslots="1" FixedInSubslots="1"/>
            <SubmoduleItemRef SubmoduleItemTarget="IDS_4CH"
                              AllowedInSubslots="2"/>
            <SubmoduleItemRef SubmoduleItemTarget="IDS_8CH"
                              AllowedInSubslots="2"/>
          </UseableSubmodules>
        </ModuleItem>
      </ModuleList>
      <SubmoduleList>
        <SubmoduleItem ID="IDS_TOTAL" SubmoduleIdentNumber="0x00000001">
          <IOData>
            <Input><DataItem DataType="Unsigned16"/></Input>
          </IOData>
        </SubmoduleItem>
        <SubmoduleItem ID="IDS_4CH" SubmoduleIdentNumber="0x00000114">
          <IOData>
            <Input><DataItem DataType="OctetString" Length="40"/></Input>
            <Output><DataItem DataType="OctetString" Length="8"/></Output>
          </IOData>
        </SubmoduleItem>
        <SubmoduleItem ID="IDS_8CH" SubmoduleIdentNumber="0x00000118">
          <IOData>
            <Input><DataItem DataType="OctetString" Length="80"/></Input>
            <Output><DataItem DataType="OctetString" Length="16"/></Output>
          </IOData>
        </SubmoduleItem>
      </SubmoduleList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""

    def test_submodule_catalog_parsed(self):
        dev = _device_from_xml(self.GSDML_WITH_SUBMODULE_LIST)
        assert len(dev.submodule_catalog) == 3
        assert dev.submodule_catalog["IDS_TOTAL"].input_length == 2
        assert dev.submodule_catalog["IDS_4CH"].input_length == 40
        assert dev.submodule_catalog["IDS_8CH"].output_length == 16

    def test_module_useable_submodules(self):
        dev = _device_from_xml(self.GSDML_WITH_SUBMODULE_LIST)
        pwr = dev.modules["IDM_PWR"]
        assert "IDS_TOTAL" in pwr.useable_submodules
        assert "IDS_4CH" in pwr.useable_submodules
        assert "IDS_8CH" in pwr.useable_submodules

    def test_module_fixed_subslots(self):
        dev = _device_from_xml(self.GSDML_WITH_SUBMODULE_LIST)
        pwr = dev.modules["IDM_PWR"]
        assert pwr.fixed_subslots == {"IDS_TOTAL": [1]}

    def test_build_io_slots_fixed_only(self):
        """Without submodule_assignment, only fixed subslots are included."""
        dev = _device_from_xml(self.GSDML_WITH_SUBMODULE_LIST)
        slots = dev.build_io_slots()
        pwr_slots = [s for s in slots if s.slot == 2]
        assert len(pwr_slots) == 1  # Only IDS_TOTAL (fixed)
        assert pwr_slots[0].subslot == 1
        assert pwr_slots[0].input_length == 2
        assert pwr_slots[0].module_ident == 0x1000032A

    def test_build_io_slots_with_submodule_assignment(self):
        """User selects IDS_8CH for subslot 2 of the power module."""
        dev = _device_from_xml(self.GSDML_WITH_SUBMODULE_LIST)
        slots = dev.build_io_slots(submodule_assignment={2: {2: "IDS_8CH"}})
        pwr_slots = [s for s in slots if s.slot == 2]
        assert len(pwr_slots) == 2
        # Subslot 1: IDS_TOTAL (fixed)
        assert pwr_slots[0].subslot == 1
        assert pwr_slots[0].input_length == 2
        # Subslot 2: IDS_8CH (user-assigned)
        assert pwr_slots[1].subslot == 2
        assert pwr_slots[1].input_length == 80
        assert pwr_slots[1].output_length == 16
        assert pwr_slots[1].submodule_ident == 0x00000118

    def test_build_io_slots_from_device_with_catalog(self):
        """Runtime matching resolves catalog submodules by ident."""
        dev = _device_from_xml(self.GSDML_WITH_SUBMODULE_LIST)

        @dataclass
        class FakeSlot:
            slot: int
            subslot: int
            module_ident: int = 0
            submodule_ident: int = 0

        device_slots = [
            FakeSlot(1, 1, 0x10000000, 0x20000000),  # IDM_DEV inline
            FakeSlot(2, 1, 0x1000032A, 0x00000001),  # IDS_TOTAL
            FakeSlot(2, 2, 0x1000032A, 0x00000114),  # IDS_4CH
        ]
        slots = dev.build_io_slots_from_device(device_slots)
        assert slots[0].input_length == 2  # Integer16
        assert slots[0].output_length == 2  # Unsigned16
        assert slots[1].input_length == 2  # IDS_TOTAL
        assert slots[2].input_length == 40  # IDS_4CH
        assert slots[2].output_length == 8

    def test_inline_module_unaffected(self):
        """Module with VirtualSubmoduleList still works alongside UseableSubmodules."""
        dev = _device_from_xml(self.GSDML_WITH_SUBMODULE_LIST)
        slots = dev.build_io_slots()
        dev_slots = [s for s in slots if s.slot == 1]
        assert len(dev_slots) == 1
        assert dev_slots[0].input_length == 2
        assert dev_slots[0].output_length == 2
