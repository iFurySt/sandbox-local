package model

import "fmt"

func (p SeatbeltPolicy) Validate() error {
	switch p.DefaultAction {
	case "", SeatbeltDefaultDeny, SeatbeltDefaultAllow:
		return nil
	default:
		return fmt.Errorf("unsupported seatbelt default action %q: expected deny or allow", p.DefaultAction)
	}
}
