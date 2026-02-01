package utils

// String returns a pointer to the string value passed in.
func String(v string) *string {
	return &v
}

// StringValue returns the value of the string pointer passed in or "" if the pointer is nil.
func StringValue(v *string) string {
	if v != nil {
		return *v
	}
	return ""
}

// Bool returns a pointer to the bool value passed in.
func Bool(v bool) *bool {
	return &v
}

// BoolValue returns the value of the bool pointer passed in or false if the pointer is nil.
func BoolValue(v *bool) bool {
	if v != nil {
		return *v
	}
	return false
}

// Int returns a pointer to the int value passed in.
func Int(v int) *int {
	return &v
}

// IntValue returns the value of the int pointer passed in or 0 if the pointer is nil.
func IntValue(v *int) int {
	if v != nil {
		return *v
	}
	return 0
}

// Int8 returns a pointer to the int8 value passed in.
func Int8(v int8) *int8 {
	return &v
}

// Int8Value returns the value of the int8 pointer passed in or 0 if the pointer is nil.
func Int8Value(v *int8) int8 {
	if v != nil {
		return *v
	}
	return 0
}

// Int64 returns a pointer to the int64 value passed in.
func Int64(v int64) *int64 {
	return &v
}

// RInt64 returns the int64 value from a pointer.
func RInt64(p *int64) int64 {
	if p != nil {
		return *p
	}
	return 0
}

// Int64Value returns the value of the int64 pointer passed in or 0 if the pointer is nil.
func Int64Value(v *int64) int64 {
	if v != nil {
		return *v
	}
	return 0
}
