package encerrors

import "errors"

var (
	// ErrInvalidKeyLength occurs when a key has been used with an invalid length
	ErrInvalidKeyLength = errors.New("goenc: invalid key length")
	// ErrInvalidMessageLength occurs when a message doesn't match the expected block size, etc
	ErrInvalidMessageLength = errors.New("goenc: invalid message length")
	// ErrInvalidSum occurs when a MAC checksum doesn't match
	ErrInvalidSum = errors.New("goenc: invalid checksum")
	// ErrInvalidPadding occurs when a key/message has been padded improperly
	ErrInvalidPadding = errors.New("goenc: invalid badding")
	// ErrInvalidMessageID occurs when a message may have been replayed
	ErrInvalidMessageID = errors.New("goenc: invalid message id, message may have been replayed")
	// ErrInvalidCipherKind occurs when an invalid cipher is selected
	ErrInvalidCipherKind = errors.New("goenc: invalid cipher kind")
	// ErrNoPadProvided occurs when no pad is given to NaCL
	ErrNoPadProvided = errors.New("goenc: no pad provided, this kind of cipher requires a pad")
)
