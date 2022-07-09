#!/bin/bash

export SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so
export SOFTHSM2_CONF=./sofhsm2.conf

rm -rf TestTokenA
softhsm2-util --show-slots
softhsm2-util --init-token --free --label TestTokenA --pin 1234 --so-pin 123456
mv $(ls -d ./*-????-????-*/) TestTokenA
SLOT_ID=$(pkcs11-tool --module=$SOFTHSM2_LIB -T | grep -B1 "TestTokenA" | grep "slot ID" | grep -oP "\(0x.*\)")
SLOT_ID=${SLOT_ID/\(/}
SLOT_ID=${SLOT_ID/\)/}
echo $SLOT_ID > TestTokenA/slot.id

pkcs11-tool --module=$SOFTHSM2_LIB --token-label TestTokenA --keypairgen --key-type RSA:1024 --usage-sign --label RSA1K_sign_101 --pin 1234 --id 101
pkcs11-tool --module=$SOFTHSM2_LIB --token-label TestTokenA --keypairgen --key-type RSA:1024 --usage-decrypt --label RSA1K_dec_102 --pin 1234 --id 102
pkcs11-tool --module=$SOFTHSM2_LIB --token-label TestTokenA --keypairgen --key-type EC:prime256v1 --usage-sign --label ECP256_sign_201 --pin 1234 --id 201
pkcs11-tool --module=$SOFTHSM2_LIB --token-label TestTokenA --keypairgen --key-type EC:prime256v1 --usage-derive --label ECP256_dh_203 --pin 1234 --id 203
pkcs11-tool --module=$SOFTHSM2_LIB --token-label TestTokenA --pin 1234 --write-object ./data01.txt --type data --label PubData1 --id 301 --application-label AppLabel1
pkcs11-tool --module=$SOFTHSM2_LIB --token-label TestTokenA --pin 1234 --write-object ./data01.txt --type data --label PrivData2 --id 302 --application-label AppLabel2 --private

pkcs11-dump dump $SOFTHSM2_LIB $SLOT_ID 1234 > TestTokenA/dump.txt
echo "TestTokenA generated. Slot id: $SLOT_ID"
echo "  full content available in TestTokenA/dump.txt"
