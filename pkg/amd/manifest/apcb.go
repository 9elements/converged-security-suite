package manifest

const APCBCookie = 0x42435041  // "APCB"

type APCB struct {
	// Cookie should be equal to APCBCookie
	Cookie uint32
}