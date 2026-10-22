package aopctl

// Event reports progress to a request's Progress callback, which runs
// synchronously, on the workflow's goroutine. The set of events may grow,
// so a type switch over them needs a default case.
type Event interface {
	isEvent()
}

// CertificateUploaded reports an upload. The workflow then waits for the
// certificate to become active.
type CertificateUploaded struct {
	CertID string
}

// AssociationRequested reports that the request to point the hostnames at a
// certificate is about to be sent.
type AssociationRequested struct {
	CertID    string
	Hostnames []string
}

// CertificateSkipped reports a prune decision not to delete a certificate,
// made while planning. HostnamePrunePlan.Skipped holds the same decisions.
type CertificateSkipped struct {
	PruneSkip
}

// CertificateRefused reports a prune target that came into use after the
// plan, so it was not deleted.
type CertificateRefused struct {
	CertID    string
	Hostnames []string
}

// CertificateDeleteFailed reports a prune target that was not deleted, or
// whose deletion did not finish.
type CertificateDeleteFailed struct {
	CertID string
	Err    error
}

// CertificateDeleted reports a prune target that is gone.
type CertificateDeleted struct {
	CertID string
}

func (CertificateUploaded) isEvent()     {}
func (AssociationRequested) isEvent()    {}
func (CertificateSkipped) isEvent()      {}
func (CertificateRefused) isEvent()      {}
func (CertificateDeleteFailed) isEvent() {}
func (CertificateDeleted) isEvent()      {}

func emit(progress func(Event), e Event) {
	if progress != nil {
		progress(e)
	}
}
