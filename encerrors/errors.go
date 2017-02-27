package encerrors

import "errors"

var (
	// ErrInvalidKeyLength repesents when a key has been used with an invalid length
	ErrInvalidKeyLength     = errors.New("goenc: invalid key length")
	ErrInvalidMessageLength = errors.New("goenc: invalid message length")
	ErrInvalidSum           = errors.New("goenc: invalid checksum")
	ErrInvalidPadding       = errors.New("goenc: invalid badding")
	ErrInvalidMessageID     = errors.New("goenc: invalid message id, message may have been replayed")
	ErrInvalidCipherKind    = errors.New("goenc: invalid cipher kind")
	ErrNoPadProvided        = errors.New("goenc: no pad provided, this kind of cipher requires a pad")
)
