package swu

import "errors"

// EAPDirectCredentials returns copies of RES/RAND/AUTN captured only after a
// successful EAP-AKA MAC check in this live SWu generation.
func (s *Session) EAPDirectCredentials() (res, rand, autn []byte) {
	if s == nil {
		return nil, nil, nil
	}
	s.eapCredentialMu.Lock()
	defer s.eapCredentialMu.Unlock()
	return append([]byte(nil), s.eapDirectRES...), append([]byte(nil), s.eapDirectRAND...), append([]byte(nil), s.eapDirectAUTN...)
}

func (s *Session) beginEAPDirectExchange() uint64 {
	s.eapCredentialMu.Lock()
	defer s.eapCredentialMu.Unlock()
	s.clearEAPDirectCredentialsLocked()
	s.eapCredentialEpoch++
	return s.eapCredentialEpoch
}

func (s *Session) saveEAPDirectCredentials(epoch uint64, res, rand, autn []byte) error {
	if len(res) < 4 || len(res) > 16 || len(rand) != 16 || len(autn) != 16 {
		return errors.New("EAP direct credential tuple has invalid lengths")
	}
	s.eapCredentialMu.Lock()
	defer s.eapCredentialMu.Unlock()
	if epoch != s.eapCredentialEpoch {
		return errors.New("EAP direct credential generation was retired")
	}
	s.eapDirectRES = append([]byte(nil), res...)
	s.eapDirectRAND = append([]byte(nil), rand...)
	s.eapDirectAUTN = append([]byte(nil), autn...)
	return nil
}

func (s *Session) clearEAPDirectCredentials() {
	if s == nil {
		return
	}
	s.eapCredentialMu.Lock()
	defer s.eapCredentialMu.Unlock()
	s.clearEAPDirectCredentialsLocked()
	s.eapCredentialEpoch++
}

func (s *Session) clearEAPDirectCredentialsLocked() {
	clear(s.eapDirectRES)
	clear(s.eapDirectRAND)
	clear(s.eapDirectAUTN)
	s.eapDirectRES, s.eapDirectRAND, s.eapDirectAUTN = nil, nil, nil
}

func (s *Session) permanentEAPIdentity() string {
	if s.eapPermanentIdentity == "" {
		s.eapPermanentIdentity = s.cfg.EAPIdentity
		if s.eapPermanentIdentity == "" {
			imsi, _ := s.cfg.SIM.GetIMSI()
			s.eapPermanentIdentity = buildNAI(imsi, s.cfg)
		}
	}
	return s.eapPermanentIdentity
}
