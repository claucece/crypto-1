package utils

import (
	"errors"

	. "gopkg.in/check.v1"
)

func (s *UtilsSuite) Test_ReturnFirstError(c *C) {
	err1 := errors.New("new error 1")
	err2 := errors.New("new error 2")

	err := FirstError(err1, err2)

	c.Assert(err, ErrorMatches, "new error 1")
}
