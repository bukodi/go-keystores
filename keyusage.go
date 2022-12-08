package keystores

type KeyUsage string

const KeyUsageSign = "sign"
const KeyUsageDecrypt = "decrypt"
const KeyUsageAgree = "agree"
const KeyUsageUnwrap = "unwrap"
const KeyUsageDerive = "derive"
