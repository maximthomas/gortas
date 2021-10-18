package errors

type AuthFailed struct {
	msg string
}

func NewAuthFailed(msg string) *AuthFailed {
	return &AuthFailed{msg: msg}
}

func (e *AuthFailed) Error() string { return e.msg }
