import re
import enum


import idc
import idaapi
import ida_ida
import ida_bytes
import ida_idaapi
import ida_kernwin


SIGNATURE_REGEX = re.compile(r"\\x[0-9A-F]{2}")
SIGNATURE_REGEX_2 = re.compile(r"((?:0x[0-9A-F]{2})+)")


PLUGIN_NAME = "SigMaker"
PLUGIN_VERSION = "1.0.0"


# Signature types and structures
class SignatureType(enum.Enum):
    IDA = 0
    x64Dbg = 1
    Signature_Mask = 2
    SignatureByteArray_Bitmask = 3


class SignatureByte:
    def __init__(self, value, is_wildcard):
        self.value = value
        self.is_wildcard = is_wildcard


Signature = list[SignatureByte]


# Output functions
def build_ida_signature_string(signature: Signature, doubleQM: bool = False) -> str:
    result = []
    # Build hex pattern
    for byte in signature:
        if byte.is_wildcard:
            result.append("??" if doubleQM else "?")
        else:
            result.append(f"{byte.value:02X}")
        result.append(" ")
    str_result = "".join(result).rstrip()
    return str_result


def build_byte_array_with_mask_signature_string(signature: Signature) -> str:
    pattern = []
    mask = []
    # Build hex pattern
    for byte in signature:
        pattern.append(f"\\x{byte.value:02X}" if not byte.is_wildcard else "\\x00")
        mask.append("x" if not byte.is_wildcard else "?")
    return "".join(pattern) + " " + "".join(mask)


def build_bytes_with_bitmask_signature_string(signature: Signature) -> str:
    pattern = []
    mask = []
    # Build hex pattern
    for byte in signature:
        pattern.append(f"0x{byte.value:02X}, " if not byte.is_wildcard else "0x00, ")
        mask.append("1" if not byte.is_wildcard else "0")
    pattern_str = "".join(pattern).rstrip(", ")
    mask_str = "".join(mask)[::-1]  # Reverse bitmask
    return pattern_str + " 0b" + mask_str


def format_signature(signature: Signature, sig_type: SignatureType) -> str:
    if sig_type == SignatureType.IDA:
        return build_ida_signature_string(signature)
    elif sig_type == SignatureType.x64Dbg:
        return build_ida_signature_string(signature, True)
    elif sig_type == SignatureType.Signature_Mask:
        return build_byte_array_with_mask_signature_string(signature)
    elif sig_type == SignatureType.SignatureByteArray_Bitmask:
        return build_bytes_with_bitmask_signature_string(signature)
    return ""


# Utility functions
def add_byte_to_signature(signature: Signature, address, wildcard: bool):
    byte = SignatureByte(ida_bytes.get_byte(address), wildcard)
    signature.append(byte)


def add_bytes_to_signature(signature: Signature, address, count: int, wildcard: bool):
    for i in range(count):
        add_byte_to_signature(signature, address + i, wildcard)


def trim_signature(signature: Signature):
    while signature and signature[-1].is_wildcard:
        signature.pop()


def get_regex_matches(string: str, regex: re.Pattern, matches: list[str]) -> bool:
    matches.clear()
    matches.extend(re.findall(regex, string))
    return bool(matches)


class Unexpected(Exception):
    pass


class SignatureMakerForm(ida_kernwin.Form):
    FormChangeCb: ida_kernwin.Form.FormChangeCb
    rAction: ida_kernwin.Form.RadGroupControl
    rOutputFormat: ida_kernwin.Form.RadGroupControl
    cGroupOptions: ida_kernwin.Form.ChkGroupControl

    def __init__(self):
        form = f"""\
BUTTON YES* OK
BUTTON CANCEL Cancel
{PLUGIN_NAME} v{PLUGIN_VERSION}
{{FormChangeCb}}
Select action:
<Create unique Signature for current code address:{{rCreateUniqueSig}}>
<Find shortest XREF Signature for current data or code address:{{rFindXRefSig}}>
<Copy selected code:{{rCopyCode}}>
<Search for a signature:{{rSearchSignature}}>{{rAction}}>

Output format:
<IDA Signature:{{rIDASig}}>
<x64Dbg Signature:{{rx64DbgSig}}>
<C Byte Array Signature + String mask:{{rByteArrayMaskSig}}>
<C Raw Bytes Signature + Bitmask:{{rRawBytesBitmaskSig}}>{{rOutputFormat}}>

Options:
<Wildcards for operands:{{cWildcardOperands}}>
<Continue when leaving function scope:{{cContinueOutside}}>{{cGroupOptions}}>
"""
        controls = {
            "FormChangeCb": ida_kernwin.Form.FormChangeCb(self.OnFormChange),
            "rAction": ida_kernwin.Form.RadGroupControl(
                (
                    "rCreateUniqueSig",
                    "rFindXRefSig",
                    "rCopyCode",
                    "rSearchSignature",
                )
            ),
            "rOutputFormat": ida_kernwin.Form.RadGroupControl(
                (
                    "rIDASig",
                    "rx64DbgSig",
                    "rByteArrayMaskSig",
                    "rRawBytesBitmaskSig",
                )
            ),
            "cGroupOptions": ida_kernwin.Form.ChkGroupControl(
                ("cWildcardOperands", "cContinueOutside")
            ),
        }
        super().__init__(form, controls)

    def OnFormChange(self, fid):
        # Debug output for when the form changes
        # print(f"Form changed, fid: {fid}", self.rAction.id, self.rOutputFormat.id, self.cGroupOptions.id)
        if fid == self.rAction.id:
            print(
                f"Action [{fid}] rAction changed: {self.GetControlValue(self.rAction):06x}"
            )
        elif fid == self.rOutputFormat.id:
            print(
                f"Action [{fid}] rOutputFormat changed: {self.GetControlValue(self.rOutputFormat):06x}"
            )
        elif fid == self.cGroupOptions.id:
            print(
                f"Action [{fid}] cGroupOptions changed: {self.GetControlValue(self.cGroupOptions):06x}"
            )
        return 1


# Plugin specific definitions
class PySigMaker(ida_idaapi.plugin_t):
    flags = 0

    help = ""
    comment = "Create signatures"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Alt-S"

    IS_ARM = False

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        # Check what processor we have
        PySigMaker.IS_ARM = self.is_arm()

        form = SignatureMakerForm()
        form.Compile()

        # Execute the form and get results
        ok = form.Execute()
        if not ok: return

        action = form.rAction.value
        output_format = form.rOutputFormat.value
        wildcard_operands = form.cGroupOptions.value & 1
        continue_outside_of_function = form.cGroupOptions.value & 2

        form.Free()

        sig_type = SignatureType(output_format)

        if action == 0:
            # Find unique signature for current address
            idaapi.show_wait_box("Generating signature...")

            ea = idc.get_screen_ea()
            signatures = self.generate_unique_signature_for_ea(
                ea, wildcard_operands, continue_outside_of_function
            )

            self.print_signature_for_ea(signatures, ea, sig_type)
            idaapi.hide_wait_box()

        elif action == 1:
            # Find XREFs for current selection, generate signatures up to 250 bytes length
            xref_signatures = []

            idaapi.show_wait_box(
                "Finding references and generating signatures. This can take a while..."
            )

            ea = idc.get_screen_ea()
            self.find_xrefs(
                ea,
                wildcard_operands,
                continue_outside_of_function,
                xref_signatures,
                250,
            )
            # Print top 5 shortest signatures
            self.print_xref_signatures_for_ea(ea, xref_signatures, sig_type, 5)
            idaapi.hide_wait_box()

        elif action == 2:
            # Print selected code as signature
            success, start, end = ida_kernwin.read_range_selection(idaapi.get_current_viewer())
            if success:
                idaapi.show_wait_box("Please stand by...")
                self.print_selected_code((start, end), sig_type, wildcard_operands)
                idaapi.hide_wait_box()
            else:
                idc.msg("Select a range to copy the code\n")

        elif action == 3:
            # Search for a signature
            input_signature = idaapi.ask_str("", idaapi.HIST_SRCH, "Enter a signature")
            if input_signature:
                idaapi.show_wait_box("Searching...")
                self.search_signature_string(input_signature)
                idaapi.hide_wait_box()

    def is_arm(self) -> bool:
        return "ARM" in ida_ida.inf_get_procname()

    def get_operand_offset_arm(self, instruction, operand_offset, operand_length):
        for op in instruction.ops:
            if op.type in {
                idaapi.o_mem,
                idaapi.o_far,
                idaapi.o_near,
                idaapi.o_phrase,
                idaapi.o_displ,
                idaapi.o_imm,
            }:
                operand_offset[0] = op.offb
                operand_length[0] = (
                    3 if instruction.size == 4 else 7 if instruction.size == 8 else 0
                )
                return True
        return False

    def get_operand(self, instruction, operand_offset, operand_length):
        if self.IS_ARM:
            return self.get_operand_offset_arm(instruction, operand_offset, operand_length)

        for op in instruction.ops:
            if op.type != idaapi.o_void and op.offb != 0:
                operand_offset[0] = op.offb
                operand_length[0] = instruction.size - op.offb
                return True
        return False

    def find_signature_occurences(self, ida_signature: str) -> list:
        binary_pattern = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(
            binary_pattern, ida_ida.inf_get_min_ea(), ida_signature, 16
        )

        results = []
        ea = ida_ida.inf_get_min_ea()
        while True:
            occurence = ida_bytes.bin_search3(
                ea,
                ida_ida.inf_get_max_ea(),
                binary_pattern,
                ida_bytes.BIN_SEARCH_NOCASE | ida_bytes.BIN_SEARCH_FORWARD,
            )[0]

            if occurence == idaapi.BADADDR:
                return results
            results.append(occurence)
            ea = occurence + 1

    def is_signature_unique(self, ida_signature: str) -> bool:
        return len(self.find_signature_occurences(ida_signature)) == 1

    def generate_unique_signature_for_ea(
        self,
        ea,
        wildcard_operands,
        continue_outside_of_function,
        max_signature_length=1000,
        ask_longer_signature=True,
    ):
        if ea == idaapi.BADADDR:
            raise Unexpected("Invalid address")
        if not idaapi.is_code(ida_bytes.get_flags(ea)):
            raise Unexpected("Cannot create code signature for data")

        signature = []
        sig_part_length = 0
        current_function = idaapi.get_func(ea)
        current_address = ea

        while True:
            if idaapi.user_cancelled():
                raise Unexpected("Aborted")

            instruction = idaapi.insn_t()
            current_instruction_length = idaapi.decode_insn(
                instruction, current_address
            )
            if current_instruction_length <= 0:
                if not signature:
                    raise Unexpected("Failed to decode first instruction")

                idc.msg(
                    f"Signature reached end of executable code @ {current_address:X}\n"
                )
                signature_string = build_ida_signature_string(signature)
                idc.msg(f"NOT UNIQUE Signature for {ea:X}: {signature_string}\n")
                raise Unexpected("Signature not unique")

            if sig_part_length > max_signature_length:
                if ask_longer_signature:
                    result = idaapi.ask_yn(
                        idaapi.ASKBTN_YES,
                        f"Signature is already at {len(signature)} bytes. Continue?",
                    )
                    if result == 1:  # Yes
                        sig_part_length = 0
                    elif result == 0:  # No
                        signature_string = build_ida_signature_string(signature)
                        idc.msg(
                            f"NOT UNIQUE Signature for {ea:X}: {signature_string}\n"
                        )
                        raise Unexpected("Signature not unique")
                    else:  # Cancel
                        raise Unexpected("Aborted")
                else:
                    raise Unexpected("Signature exceeded maximum length")

            sig_part_length += current_instruction_length

            operand_offset = [0]
            operand_length = [0]
            if (
                wildcard_operands
                and self.get_operand(instruction, operand_offset, operand_length)
                and operand_length[0] > 0
            ):
                add_bytes_to_signature(
                    signature, current_address, operand_offset[0], False
                )
                add_bytes_to_signature(
                    signature,
                    current_address + operand_offset[0],
                    operand_length[0],
                    True,
                )
                if operand_offset[0] == 0:
                    add_bytes_to_signature(
                        signature,
                        current_address + operand_length[0],
                        current_instruction_length - operand_length[0],
                        False,
                    )
            else:
                add_bytes_to_signature(
                    signature, current_address, current_instruction_length, False
                )

            current_sig = build_ida_signature_string(signature)
            if self.is_signature_unique(current_sig):
                trim_signature(signature)
                return signature

            current_address += current_instruction_length

            if (
                not continue_outside_of_function
                and current_function
                and idaapi.get_func(current_address) != current_function
            ):
                raise Unexpected("Signature left function scope")

        raise Unexpected("Unknown")

    def generate_signature_for_ea_range(self, ea, wildcard_operands):
        if ea[0] == idaapi.BADADDR or ea[1] == idaapi.BADADDR:
            raise Unexpected("Invalid address")

        signature = []
        sig_part_length = 0

        if not idaapi.is_code(ida_bytes.get_flags(ea[0])):
            add_bytes_to_signature(signature, ea[0], ea[1] - ea[0], False)
            return signature

        current_address = ea[0]
        while True:
            if idaapi.user_cancelled():
                raise Unexpected("Aborted")

            instruction = idaapi.insn_t()
            current_instruction_length = idaapi.decode_insn(
                instruction, current_address
            )
            if current_instruction_length <= 0:
                if not signature:
                    raise Unexpected("Failed to decode first instruction")

                idc.msg(
                    f"Signature reached end of executable code @ {current_address:X}\n"
                )
                if current_address < ea[1]:
                    add_bytes_to_signature(
                        signature, current_address, ea[1] - current_address, False
                    )
                trim_signature(signature)
                return signature

            sig_part_length += current_instruction_length

            operand_offset = [0]
            operand_length = [0]
            if (
                wildcard_operands
                and self.get_operand(instruction, operand_offset, operand_length)
                and operand_length[0] > 0
            ):
                add_bytes_to_signature(
                    signature, current_address, operand_offset[0], False
                )
                add_bytes_to_signature(
                    signature,
                    current_address + operand_offset[0],
                    operand_length[0],
                    True,
                )
                if operand_offset[0] == 0:
                    add_bytes_to_signature(
                        signature,
                        current_address + operand_length[0],
                        current_instruction_length - operand_length[0],
                        False,
                    )
            else:
                add_bytes_to_signature(
                    signature, current_address, current_instruction_length, False
                )

            current_address += current_instruction_length

            if current_address >= ea[1]:
                trim_signature(signature)
                return signature

        raise Unexpected("Unknown")

    def print_signature_for_ea(self, signature, ea, sig_type):
        if not signature:
            idc.msg(f"Error: {signature}\n")
            return
        signature_str = format_signature(signature, sig_type)
        idc.msg(f"Signature for {ea:X}: {signature_str}\n")

    def find_xrefs(
        self,
        ea,
        wildcard_operands,
        continue_outside_of_function,
        xref_signatures,
        max_signature_length,
        max_xrefs=1000,
    ):
        xref = idaapi.xrefblk_t()
        xref_count = 0

        shortest_signature_length = max_signature_length + 1

        xref_ok = xref.first_to(ea, idaapi.XREF_FAR)
        while xref_ok and xref_count < max_xrefs:
            if not idaapi.is_code(ida_bytes.get_flags(xref.frm)):
                continue
            xref_ok = xref.next_to()
            xref_count += 1

        iteration = 0
        xref_ok = xref.first_to(ea, idaapi.XREF_FAR)
        while xref_ok and iteration < max_xrefs:
            iteration += 1

            if idaapi.user_cancelled():
                break
            if not idaapi.is_code(ida_bytes.get_flags(xref.frm)):
                continue

            shortest_signature = 0
            if shortest_signature_length <= max_signature_length:
                shortest_signature = shortest_signature_length
            idaapi.replace_wait_box(
                f"Processing xref {iteration} of {xref_count}"
                f"({(iteration / xref_count) * 100.0:.1f}%)...\n\n"
                f"Suitable Signatures: {len(xref_signatures)}\n"
                f"Shortest Signature: {shortest_signature} Bytes"
            )

            signature = self.generate_unique_signature_for_ea(
                xref.frm,
                wildcard_operands,
                continue_outside_of_function,
                max_signature_length,
                False,
            )

            if not signature: continue

            if len(signature) < shortest_signature_length:
                shortest_signature_length = len(signature)

            xref_signatures.append((xref.frm, signature))
            xref_ok = xref.next_to()

        xref_signatures.sort(key=lambda x: len(x[1]))


    def print_xref_signatures_for_ea(self, ea, xref_signatures, sig_type, top_count):
        if not xref_signatures:
            idc.msg("No XREFs have been found for your address\n")
            return

        top_length = min(top_count, len(xref_signatures))
        idc.msg(
            f"Top {top_length} Signatures out of {len(xref_signatures)} xrefs for {ea:X}:\n"
        )
        for i in range(top_length):
            origin_address, signature = xref_signatures[i]
            signature_str = format_signature(signature, sig_type)
            idc.msg(f"XREF Signature #{i + 1} @ {origin_address:X}: {signature_str}\n")

    def print_selected_code(self, ea, sig_type, wildcard_operands):
        selection_size = ea[1] - ea[0]
        assert selection_size > 0

        signature = self.generate_signature_for_ea_range(ea, wildcard_operands)
        if not signature:
            idc.msg(f"Error: {signature}\n")
            return

        signature_str = format_signature(signature, sig_type)
        idc.msg(f"Code for {ea[0]:X}-{ea[1]:X}: {signature_str}\n")

    def search_signature_string(self, input):
        converted_signature_string = ""
        string_mask = ""

        match = re.search(r"x[x?]+", input)
        if match:
            string_mask = match.group(0)
        else:
            match = re.search(r"0b[0,1]+", input)
            if match:
                bits = match.group(0)[2:]
                reversed_bits = bits[::-1]
                string_mask = "".join("x" if b == "1" else "?" for b in reversed_bits)

        if string_mask:
            raw_byte_strings = []
            if get_regex_matches(input, SIGNATURE_REGEX, raw_byte_strings) and len(
                raw_byte_strings
            ) == len(string_mask):
                converted_signature = []
                for i, m in enumerate(raw_byte_strings):
                    b = SignatureByte(int(m[2:], 16), string_mask[i] == "?")
                    converted_signature.append(b)
                converted_signature_string = build_ida_signature_string(
                    converted_signature
                )
            elif get_regex_matches(input, SIGNATURE_REGEX_2, raw_byte_strings) and len(
                raw_byte_strings
            ) == len(string_mask):
                converted_signature = []
                for i, m in enumerate(raw_byte_strings):
                    b = SignatureByte(int(m[2:], 16), string_mask[i] == "?")
                    converted_signature.append(b)
                converted_signature_string = build_ida_signature_string(
                    converted_signature
                )
            else:
                idc.msg(
                    f'Detected mask "{string_mask}" but failed to match corresponding bytes\n'
                )
        else:
            input = re.sub(r"[)(\[\]]+", "", input)
            input = re.sub(r"^\s+", "", input)
            input = re.sub(r"[? ]+$", "", input) + " "
            input = re.sub(r"\\?\\x", "", input)  # Simplify hex pattern matching
            input = re.sub(r"\s+", " ", input)  # Normalize spaces
            converted_signature_string = input

        if not converted_signature_string:
            idc.msg("Unrecognized signature type\n")
            return

        idc.msg(f"Signature: {converted_signature_string}\n")
        signature_matches = self.find_signature_occurences(converted_signature_string)
        if not signature_matches:
            idc.msg("Signature does not match!\n")
            return
        for ea in signature_matches:
            idc.msg(f"Match @ {ea:X}\n")


def PLUGIN_ENTRY():
    return PySigMaker()
