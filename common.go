package p2pact

import _ "embed"

// CommonDict is the common dictionary (spec §5, dict/common-1.zdict of the spec repository):
// trained on open conversations, the same for everyone. A device that has it compresses with it
// until it has trained its own for a device: n.AddDict(p2pact.CommonDict).
//
//go:embed dict/common-1.zdict
var CommonDict []byte
