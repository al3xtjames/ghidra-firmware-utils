#!/bin/sh

if [ -z "$EDK2_PATH" ]; then
    echo "EDK2_PATH is not set"
    exit 1
fi

if [ -z "$ARCH" ]; then
    echo "ARCH is not set"
    exit 1
fi

cat << EOF > "uefi_$(echo $ARCH | tr '[:upper:]' '[:lower:]').prf"
Uefi/UefiBaseType.h
Uefi/UefiSpec.h
PiDxe.h
PiMm.h
PiPei.h
PiSmm.h
Library/DxeCoreEntryPoint.h
Library/PeiCoreEntryPoint.h
Library/PeimEntryPoint.h
Library/StandaloneMmDriverEntryPoint.h
Library/UefiApplicationEntryPoint.h
Library/UefiDriverEntryPoint.h
$(find "$EDK2_PATH/MdePkg/Include/Pi" -type f)
$(find "$EDK2_PATH/MdePkg/Include/Ppi" -type f)
$(find "$EDK2_PATH/MdePkg/Include/Protocol" -type f)
$(find "$EDK2_PATH/MdePkg/Include/IndustryStandard" -type f)

-I"$EDK2_PATH/MdePkg/Include/$ARCH"
-I"$EDK2_PATH/MdePkg/Include"
EOF
