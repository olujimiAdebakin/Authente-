package handler



import (
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var Validate *validator.Validate

func InitValidator() {
	Validate = validator.New()

	// Allow only alphabets and spaces for names
	Validate.RegisterValidation("alphaSpace", func(fl validator.FieldLevel) bool {
		re := regexp.MustCompile(`^[a-zA-Z\s]+$`)
		return re.MatchString(fl.Field().String())
	})

	// Enforce strong password policy:
	// - at least one lowercase
	// - at least one uppercase
	// - at least one number
	// - at least one special character
	// - at least 8 chars total
	Validate.RegisterValidation("password", func(fl validator.FieldLevel) bool {
		re := regexp.MustCompile(`^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$`)
		return re.MatchString(fl.Field().String())
	})

}

func FormatValidationError(err error) map[string]string {
	errs := make(map[string]string)
	for _, e := range err.(validator.ValidationErrors) {
		// Here is a more user-friendly error messages
		switch e.Tag() {
		case "required":
			errs[strings.ToLower(e.Field())] = "This field is required"
		case "email":
			errs[strings.ToLower(e.Field())] = "Invalid email format"
		case "min":
			errs[strings.ToLower(e.Field())] = "Value is too short"
		case "password":
			errs[strings.ToLower(e.Field())] = "Password must contain uppercase, lowercase, number, and special character"
		case "alphaSpace":
			errs[strings.ToLower(e.Field())] = "Only letters and spaces are allowed"
		default:
			errs[strings.ToLower(e.Field())] = "Invalid value"
		}
	}
	return errs
}

