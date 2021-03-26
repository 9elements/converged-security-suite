package cbnt

import "fmt"

var (
	crossSVN = Test{
		Name:     "KM/BPM SVN identical",
		function: KMBPMSVNidentical,
		Type:     required,
	}
)

var imageCrossTests = []*Test{
	&crossSVN,
}

// KMBPMSVNidentical defines the behavior for the Test "KM/BPM SVN identical"
func KMBPMSVNidentical() (bool, error) {
	if objUnderTest.km.KMSVN.SVN() != objUnderTest.bpm.BPMH.BPMSVN.SVN() {
		return false, fmt.Errorf("KMSVN: %d, BPMSVN: %d do not match", objUnderTest.km.KMSVN.SVN(), objUnderTest.bpm.BPMH.BPMSVN.SVN())
	}
	return true, nil
}
