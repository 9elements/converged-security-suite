#!/bin/bash

# This is how we create a dummy image:
# * Create BIOS region.
# * Create dummy NVAR, PEI and DXE volumes inside the region.
# * Create FIT (which is a one more layout table, independent to UEFI layout, but works in the same space) inside a padding inside DXE.
# * Inject KM and BPM.
#
# * It access FIT to get access to ACM, BPM and KM.
# * Then it executes ACM and uses BPM to jump to PEI.
# * Then PEI parses the UEFI layout and after pre-EFI initialization jumps to DXE.
#
# Also in real images usually:
# * FIT, FIT pointer, legacy reset vector, KM, BPM and microcodes are placed in paddings in DXE.
# * ACM is placed into a padding between PEI and DXE.

# == Parsing arguments ==

errorExit() {
    ERROR="$1"; shift
    echo "error: $ERROR" >&2
    echo "syntax $0 <output_file>" >&2
    exit 1
}

OUTPUT_FILE="$1"; shift
if [[ "$OUTPUT_FILE" = "" ]]; then
    errorExit "no output file entered"
fi

if [[ -e "$OUTPUT_FILE" ]]; then
    errorExit "'$OUTPUT_FILE' already exists, exiting to avoid overwriting"
fi

# == Initializing the process ==

set -e

FBSOURCE="$HOME/fbsource"

declare -A DEPENDENCIES
setDependency() {
    PATH_VARIABLE_NAME="$1"; shift
    IMPORT_PATH="$1"; shift
    if [[ "$IMPORT_PATH" = "" || "$PATH_VARIABLE_NAME" = "" ]]; then
        errorExit "an empty dependency value ('$IMPORT_PATH' '$PATH_VARIABLE_NAME')"
    fi
    if [[ "${DEPENDENCIES[$PATH_VARIABLE_NAME]}" != "" ]]; then
        errorExit "overwriting dependencies for $PATH_VARIABLE_NAME"
    fi
    go install "$IMPORT_PATH" >/dev/null 2>/dev/null &
    DEPENDENCIES[$PATH_VARIABLE_NAME]="$IMPORT_PATH"
}

prepareDependencies() {
    wait
	GO_PATH_BIN="$(go env GOPATH | awk -F ':' '{print $1}')"/bin
    for PATH_VARIABLE_NAME in "${!DEPENDENCIES[@]}"; do
        IMPORT_PATH="${DEPENDENCIES[$PATH_VARIABLE_NAME]}"
		BINARY_NAME="$(echo "$IMPORT_PATH" | sed -e 's%.*/%%g')"
        BINARY_PATH="$GO_PATH_BIN/$BINARY_NAME"
        eval "$PATH_VARIABLE_NAME=\"\$BINARY_PATH\""
    done
}

setDependency UTK github.com/linuxboot/fiano/cmds/utk
setDependency CBNTPROV github.com/9elements/converged-security-suite/v2/cmd/cbnt-prov
setDependency PCR0TOOL github.com/9elements/converged-security-suite/v2/cmd/pcr0tool
setDependency FITTOOL github.com/linuxboot/fiano/cmds/fittool

prepareDependencies


# createVolumeWithPadFile creates a volume with a pad file inside.
#
# A a pad file is important, because `fwtest` does benign injections by corrupting
# the last byte of a first pad file. And we need the second one to
createVolumeWithPadFile() {
    OFFSET="$1"; shift
    SIZE="$1"; shift
    UUID="$1"; shift

    # Creating a volume with a pid file inside of size 256 bytes
    $UTK -erase-polarity 0xFF "$OUTPUT_FILE" \
        create-fv "$OFFSET" "$SIZE" "$UUID" \
        insert pad_file 256 end "$UUID" \
        save "$OUTPUT_FILE"
}

# insertRawFile insert a raw file to a volume with a defined content
insertRawFile() {
	VOLUME_GUID="$1"; shift
	FILE_GUID="$1"; shift
	CONTENT="$1"; shift

	if [[ "${#CONTENT}" -ge 248 ]]; then
		errorExit "big file content is not supported yet"
	fi

	FILE_SIZE="$((${#CONTENT} + 24))" # len(content) + len(headers)
	$UTK "$OUTPUT_FILE" insert file <(
		# == HEADERS ==

		# GUID
		IFS=- FILE_GUID_PARTS=($FILE_GUID)
		PART_IDX=0
		for PART in ${FILE_GUID_PARTS[@]}; do
			# reverse:
			if [[ $PART_IDX -lt 3 ]]; then
				PART=$(echo "$PART"| xxd -p -r | xxd -e -g 256 -u | awk '{print $2}')
			fi
			PART_IDX=$(($PART_IDX + 1))
			# write:
			echo -n "$PART" | xxd -r -p
		done
		# Checksums. Forcing to zero for simplicity
		echo -n "00 00" | xxd -r -p
		# File Type. Raw == 1
		echo -n "01" | xxd -r -p
		# Attributes
		echo -n "00" | xxd -r -p
		# Size
		echo -n "$(printf "%02X" "$FILE_SIZE") 00 00" | xxd -r -p
		# File state. Forcing to zero for simplicity
		echo -n "00" | xxd -r -p

		# == CONTENT ==

		echo -n "$CONTENT"
	) end "$VOLUME_GUID" save "$OUTPUT_FILE"
}

# == Creating the image ==

# Create an empty image.
dd if=/dev/zero of="$OUTPUT_FILE" bs=1K count=64 2>/dev/null

# Create a PEI volume at offset 32K of size 32K.
#
# UUID "61C0F511-A691-4F54-974F-B9A42172CE53" is taken from PEI of a real UEFI image.
createVolumeWithPadFile $((32 * 1024)) $((32 * 1024)) "61C0F511-A691-4F54-974F-B9A42172CE53"

# Also inserting a file to PEI which would be used to store PCD data.
# Here we generated just a random UUID for it and then will reuse this in "parse_firmware_dummy.go".
insertRawFile "61C0F511-A691-4F54-974F-B9A42172CE53" "658ABE96-545D-4797-BDCC-B9BE16AAD5EE" "dummy-firmware"

# Create a DXE volume at offset 4K of size 16K.
#
# UUID "5C60F367-A505-419A-859E-2A4FF6CA6FE5" is taken from DXE of a real UEFI image.
createVolumeWithPadFile $((4 * 1024)) $((16 * 1024)) "5C60F367-A505-419A-859E-2A4FF6CA6FE5"

# Create a NVAR volume at offset 0K of size 4K.
#
# UUID "FA4974FC-AF1D-4E5D-BDC5-DACD6D27BAEC" is taken from an NVAR volume of a real UEFI image.
createVolumeWithPadFile $((0 * 1024)) $((4 * 1024)) "FA4974FC-AF1D-4E5D-BDC5-DACD6D27BAEC"

# Generate OEM and ODM keys
#
# Size 2048 was picked arbitrary. Just small enough to generate it fast (and make this script work fast).
OEMPRIVKEYPATH="$(mktemp)"
ODMPRIVKEYPATH="$(mktemp)"
OEMPUBKEYPATH="$(mktemp)"
ODMPUBKEYPATH="$(mktemp)"
#trap 'rm -f "$OEMPRIVKEYPATH" "$ODMPRIVKEYPATH" "$OEMPUBKEYPATH" "$ODMPUBKEYPATH"' ABRT EXIT INT
openssl genpkey -out "$OEMPRIVKEYPATH" -algorithm RSA -pkeyopt rsa_keygen_bits:2048 >/dev/null 2>/dev/null
openssl genpkey -out "$ODMPRIVKEYPATH" -algorithm RSA -pkeyopt rsa_keygen_bits:2048 >/dev/null 2>/dev/null
openssl rsa -in "$OEMPRIVKEYPATH" -pubout -out "$OEMPUBKEYPATH" 2>/dev/null
openssl rsa -in "$ODMPRIVKEYPATH" -pubout -out "$ODMPUBKEYPATH" 2>/dev/null

# Create FIT at offset 59K.
"$FITTOOL" init -f "$OUTPUT_FILE" --pointer-from-offset $(( 59 * 1024 ))

# Create a dummy ACM
DUMMYACMPATH="$(mktemp)"
"$CBNTPROV" acm-gen "$DUMMYACMPATH" --moduletype 2 --sesvn 1 --txtsvn 2 --date $((16#11223344)) --size 2048

# Inject the dummy ACM (FIT entry type 0x02) at offset 20K.
# In real images ACM is usually pleaced between PEI and DXE, so we use offset 20K.
"$FITTOOL" add_raw_headers -f "$OUTPUT_FILE" --address-offset $(( 20 * 1024 )) --type 2
dd if="$DUMMYACMPATH" of="$OUTPUT_FILE" bs=1K seek=20 conv=notrunc 2>/dev/null
rm -f "$DUMMYACMPATH"

# Create a KM.
#
# KM uses an OEM key to authorize an ODM key to issue a signed BPM. So `km-gen` will calculate
# a hash of the ODM (BPM) pubkey and store it inside KM, in turn KM is signed by the OEM (KM) key.
#
# Algorithm "SHA256" was picked arbitrary. One may use another algorithm.
KMPATH="$(mktemp)"
# Generated an unsigned KM
"$CBNTPROV" km-gen "$KMPATH" "$OEMPUBKEYPATH" --bpmpubkey "$ODMPUBKEYPATH" --pkhashalg=SHA256 --bpmhashalgo SHA256
# Sign the KM (with no password on the private key file)
"$CBNTPROV" km-sign "$KMPATH" "$KMPATH" "$OEMPRIVKEYPATH" RSASSA ""

# Inject the KM reference to FIT (FIT entry type 0x0B), by referencing it as at the offset 21K
"$FITTOOL" add_raw_headers -f "$OUTPUT_FILE" --address-offset $(( 21 * 1024 )) --size "$(stat -c %s "$KMPATH")" --type $((16#B))
dd if="$KMPATH" of="$OUTPUT_FILE" bs=1K seek=21 conv=notrunc 2>/dev/null
rm -f "$KMPATH"

# Create a BPM.
#
# BPM contains information about the firmware. Including (but not limited to):
# * Which areas to measure to PCR registers as IBB.
# * Which boot policy to use.
# * Security Version Number (SVN).
#
# BPM is signed by an ODM key, which is trusted, because its hash is included into KM, which is
# signed by the OEM key (which we trust, because OEM is us).
BPMPATH="$(mktemp)"
# `$CBNTPROV bpm-gen` (to generate an BPM) depends on scanning the FIT table of
# the image to find BIOS startup modules and include them as IBBs.
# So first we need to add at least one entry. We will use a part of the dummy PEI
# as an IBB section (similar things also happens in a real image).
"$FITTOOL" add_raw_headers -f "$OUTPUT_FILE" --address-offset $((32 * 1024)) --size $((4 * 1024 / 16)) --type $((16#7))
# Now we can execute the `$CBNTPROV bpm-gen` command
"$CBNTPROV" bpm-gen --ibbhash SHA1,SHA256 "$BPMPATH" "$OUTPUT_FILE"
# Sign the BPM (with no password on the private key file)
"$CBNTPROV" bpm-sign "$BPMPATH" "$BPMPATH" "$ODMPRIVKEYPATH" RSASSA ""

# Inject the BPM reference into FIT (FIT entry type 0x0C), by referencing it as at the offset 22K
"$FITTOOL" add_raw_headers -f "$OUTPUT_FILE" --address-offset $(( 22 * 1024 )) --size "$(stat -c %s "$BPMPATH")" --type $((16#C))
dd if="$BPMPATH" of="$OUTPUT_FILE" bs=1K seek=22 conv=notrunc 2>/dev/null
rm -f "$BPMPATH"

# That's it, a dummy image is ready (and is in "$OUTPUT_FILE") :)
"$FITTOOL" show -f "$OUTPUT_FILE"
"$PCR0TOOL" printnodes -as-tree "$OUTPUT_FILE"