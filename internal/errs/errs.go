package errs

import "strings"

// Errors is a slice of error.
type Errors []error

// Error outputs the error messages contained in Errors joined with a newline.
func (e Errors) Error() string {
	var errors strings.Builder
	len := len(e)
	for i := 0; i < len; i++ {
		errors.WriteString(e[i].Error())
		if i != len-1 {
			errors.WriteString("\n")
		}
	}
	return errors.String()
}
