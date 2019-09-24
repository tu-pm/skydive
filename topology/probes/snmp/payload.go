package snmp

import (
	"errors"
	"fmt"
	"reflect"
)

type SnmpPayload map[string]interface{}

// SetValue adds a new key-value pair to the message payload.
func (m *SnmpPayload) SetValue(k string, v interface{}) {
	switch v := v.(type) {
	case string:
		// Don't set if value is an empty string
		if len(v) == 0 {
			return
		}
	case int64:
		// Look up mappings table to get string representation
		// of current value
		if mp, ok := mappings[k]; ok {
			(*m)[k] = mp[int(v)]
			return
		}
	default:
		// Not support other value types
		return
	}
	(*m)[k] = v
}

// InitStruct convert SnmpPayload to a struct with the following
// conditions:
// 1. Map keys are the same as struct field names
// 2. Map values are of the same types as struct values
// 3. s is pointer to struct, not the struct itself
// 4. s fields have to be publicly accessible to be set value
func (m *SnmpPayload) InitStruct(s interface{}) error {
	structValue := reflect.ValueOf(s).Elem()
	for name, value := range *m {
		structFieldValue := structValue.FieldByName(name)

		if !structFieldValue.IsValid() {
			return fmt.Errorf("No such field: %s in obj", name)
		}

		// If obj field value is not settable an error is thrown
		if !structFieldValue.CanSet() {
			return fmt.Errorf("Cannot set %s field value", name)
		}

		structFieldType := structFieldValue.Type()
		val := reflect.ValueOf(value)
		if structFieldType != val.Type() {
			invalidTypeError := errors.New("Provided value type didn't match obj field type")
			return invalidTypeError
		}

		structFieldValue.Set(val)
	}
	return nil
}
