#!/bin/bash

# Define the source files in the current directory
SOURCE_DIR=$(pwd)
BLAKE2_SRC="$SOURCE_DIR/blake2.h"
HASH_TABLE_ENTRY_SRC="$SOURCE_DIR/hash_table_entry.h"
LOCKS_SRC="$SOURCE_DIR/locks.h"
IO_SRC="$SOURCE_DIR/stream_channel.hpp"
SCI_IO_SRC="$SOURCE_DIR/net_io_channel.h"
OPRF_SRC="$SOURCE_DIR/vole_oprf.hpp"
TIMER_SRC="$SOURCE_DIR/Timer.h"
CHANNEL_SRC="$SOURCE_DIR/channel.cpp"
VOLE_SRC="$SOURCE_DIR/vole.hpp"
ALSZOTE_SRC="$SOURCE_DIR/alsz_ote.hpp"
IKNPOTE_SRC="$SOURCE_DIR/iknp_ote.hpp"
NAORPINKASOT_SRC="$SOURCE_DIR/naor_pinkas_ot.hpp"
SPLIT_KKOT_SRC="$SOURCE_DIR/split-kkot.h"

# Define the target paths
BLAKE2_DST="../extern/2PC-Circuit-PSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/md/blake2.h"
HASH_TABLE_ENTRY_DST="../extern/2PC-Circuit-PSI/extern/HashingTables/common/hash_table_entry.h"
LOCKS_DST="../extern/2PC-Circuit-PSI/extern/EzPC/SCI/extern/SEAL/native/src/seal/util/locks.h"
IO_DST="../extern/Kunlun/netio/stream_channel.hpp"
SCI_IO_DST="../extern/2PC-Circuit-PSI/extern/EzPC/SCI/src/utils/net_io_channel.h"
OPRF_DST="../extern/Kunlun/mpc/oprf/vole_oprf.hpp"
TIMER_DST="../extern/2PC-Circuit-PSI/extern/libOTe/cryptoTools/cryptoTools/Common/Timer.h"
CHANNEL_DST="../extern/2PC-Circuit-PSI/extern/ABY/extern/ENCRYPTO_utils/src/ENCRYPTO_utils/channel.cpp"
VOLE_DST="../extern/Kunlun/mpc/vole/vole.hpp"
ALSZOTE_DST="../extern/Kunlun/mpc/ot/alsz_ote.hpp"
IKNPOTE_DST="../extern/Kunlun/mpc/ot/iknp_ote.hpp"
NAORPINKASOT_DST="../extern/Kunlun/mpc/ot/naor_pinkas_ot.hpp"
SPLIT_KKOT_DST="../extern/2PC-Circuit-PSI/extern/EzPC/SCI/src/OT/split-kkot.h"

# Check if source files exist
if [[ ! -f "$BLAKE2_SRC" || ! -f "$HASH_TABLE_ENTRY_SRC" || ! -f "$LOCKS_SRC" || ! -f "$IO_SRC" || ! -f "$OPRF_SRC" || ! -f "$TIMER_SRC" || ! -f "$SCI_IO_SRC" || ! -f "$CHANNEL_SRC" || ! -f "$VOLE_SRC" || ! -f "$ALSZOTE_SRC" || ! -f "$IKNPOTE_SRC" || ! -f "$NAORPINKASOT_SRC" || ! -f "$SPLIT_KKOT_SRC" ]]; then
  echo "One or more source files are missing in the current directory."
  exit 1
fi

# Copy the files
echo "Replacing blake2.h..."
cp "$BLAKE2_SRC" "$BLAKE2_DST"

echo "Replacing hash_table_entry.h..."
cp "$HASH_TABLE_ENTRY_SRC" "$HASH_TABLE_ENTRY_DST"

echo "Replacing locks.h..."
cp "$LOCKS_SRC" "$LOCKS_DST"

echo "Replacing stream_channel.hpp..."
cp "$IO_SRC" "$IO_DST"

echo "Replacing net_io_channel.h..."
cp "$SCI_IO_SRC" "$SCI_IO_DST"

echo "Replacing vole_oprf.hpp..."
cp "$OPRF_SRC" "$OPRF_DST"

echo "Replacing Timer.h..."
cp "$TIMER_SRC" "$TIMER_DST"

echo "Replacing channel.cpp..."
cp "$CHANNEL_SRC" "$CHANNEL_DST"

echo "Replacing vole.hpp..."
cp "$VOLE_SRC" "$VOLE_DST"

echo "Replacing alsz_ote.hpp..."
cp "$ALSZOTE_SRC" "$ALSZOTE_DST"

echo "Replacing iknp_ote.hpp..."
cp "$IKNPOTE_SRC" "$IKNPOTE_DST"

echo "Replacing naor_pinkas_ot.hpp..."
cp "$NAORPINKASOT_SRC" "$NAORPINKASOT_DST"

#echo "Replacing split-kkot.h..."
#cp "$SPLIT_KKOT_SRC" "$SPLIT_KKOT_DST"

echo "Files have been replaced successfully."
