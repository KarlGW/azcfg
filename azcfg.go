package azcfg

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// secretTag is the name of the tag for secrets.
	secretTag = "secret"
	// settingTag is the name of the tag for settings.
	settingTag = "setting"
)

// Parse secrets from an Azure Key Vault and settings from an
// Azure App Configuration into the provided struct.
func Parse(ctx context.Context, v any, options ...Option) error {
	parser, err := NewParser(options...)
	if err != nil {
		return fmt.Errorf("azcfg: %w", err)
	}
	return parser.Parse(ctx, v)
}

// Parse secrets into the configuration.
func parse(ctx context.Context, d any, secretClient secretClient, settingClient settingClient) error {
	v := reflect.ValueOf(d)
	if v.Kind() != reflect.Pointer {
		return errors.New("must provide a pointer to a struct")
	}
	v = reflect.ValueOf(d).Elem()
	if v.Kind() != reflect.Struct {
		return errors.New("provided value is not a struct")
	}

	values := &values{v: make(map[string]string)}
	var wg sync.WaitGroup
	errCh := make(chan error)

	secretFields, requiredSecrets := getFields(v, secretTag)
	if len(secretFields) > 0 {
		if secretClient == nil {
			return fmt.Errorf("%w: key vault name not set", ErrSecretClient)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			secrets, err := secretClient.GetSecrets(ctx, secretFields)
			if err != nil {
				errCh <- fmt.Errorf("%w: %s", ErrSecretRetrieval, err.Error())
				return
			}
			values.addSecrets(secrets)
		}()
	}

	settingFields, requiredSettings := getFields(v, settingTag)
	if len(settingFields) > 0 {
		if settingClient == nil {
			return fmt.Errorf("%w: app configuration name not set", ErrSettingClient)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			settings, err := settingClient.GetSettings(ctx, settingFields)
			if err != nil {
				errCh <- fmt.Errorf("%w: %s", ErrSettingRetrieval, err.Error())
				return
			}
			values.addSettings(settings)
		}()
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return newError(errs...)
	}

	if err := setFields(v, values.v); err != nil {
		if errors.Is(err, errRequired) {
			return newRequiredFieldsError(values.v, requiredFields{f: requiredSecrets, t: "secret"}, requiredFields{f: requiredSettings, t: "setting"})
		}
		return newError(err)
	}
	return nil
}

// getFields gets fields with the specified tag.
func getFields(v reflect.Value, tag string) ([]string, []string) {
	t := v.Type()
	fields := make([]string, 0)
	required := make([]string, 0)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Pointer && v.Field(i).Elem().Kind() == reflect.Struct {
			f, r := getFields(v.Field(i).Elem(), tag)
			fields = append(fields, f...)
			required = append(required, r...)
		} else if v.Field(i).Kind() == reflect.Struct {
			f, r := getFields(v.Field(i), tag)
			fields = append(fields, f...)
			required = append(required, r...)
		} else {
			if value, ok := t.Field(i).Tag.Lookup(tag); ok {
				tags := strings.Split(value, ",")
				fields = append(fields, tags[0])
				if isRequired(tags) {
					required = append(required, tags[0])
				}
			}
		}
	}
	return fields, required
}

// fieldFromTag gets the field from the tag.
func fieldFromTag(f reflect.StructField, tags ...string) (string, bool) {
	for _, tag := range tags {
		if v, ok := f.Tag.Lookup(tag); ok {
			return v, true
		}
	}
	return "", false
}

// setFields sets the values from the map into the struct fields.
func setFields(v reflect.Value, values map[string]string) error {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).CanSet() {
			continue
		}
		if v.Field(i).Kind() == reflect.Pointer && v.Field(i).Elem().Kind() == reflect.Struct {
			if err := setFields(v.Field(i).Elem(), values); err != nil {
				return err
			}
		} else if v.Field(i).Kind() == reflect.Struct {
			if err := setFields(v.Field(i), values); err != nil {
				return err
			}
		} else {
			field, ok := fieldFromTag(t.Field(i), secretTag, settingTag)
			if !ok {
				continue
			}
			tags := strings.Split(field, ",")
			if value, ok := values[tags[0]]; ok {
				if len(value) == 0 && isRequired(tags) {
					return errRequired
				} else if len(value) == 0 {
					continue
				}
				if v.Field(i).Kind() == reflect.Slice {
					values := splitTrim(value, ",")
					slice := reflect.MakeSlice(v.Field(i).Type(), len(values), len(values))
					for j := 0; j < slice.Cap(); j++ {
						if err := setValue(slice.Index(j), values[j]); err != nil {
							return fmt.Errorf("%w: field %s: %s", ErrSetValue, t.Field(i).Name, err.Error())
						}
					}
					v.Field(i).Set(slice)
				} else {
					if err := setValue(v.Field(i), value); err != nil {
						return fmt.Errorf("%w: field %s: %s", ErrSetValue, t.Field(i).Name, err.Error())
					}
				}
			}
		}
	}
	return nil
}

// setValue sets the new value on the incoming reflect.Value.
func setValue(v reflect.Value, val string) error {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if err := setValue(v.Elem(), val); err != nil {
			return err
		}
	case reflect.String:
		v.SetString(val)
	case reflect.Bool:
		b, err := strconv.ParseBool(val)
		if err != nil {
			return parseError(v.Type().Name())
		}
		v.SetBool(b)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i, err := strconv.ParseUint(val, 10, getBitSize(v.Kind()))
		if err != nil {
			return parseError(v.Type().Name())
		}
		v.SetUint(i)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Kind() == reflect.Int64 && v.Type() == reflect.TypeOf(time.Duration(0)) {
			d, err := time.ParseDuration(val)
			if err != nil {
				return parseError(v.Type().Name())
			}
			v.SetInt(int64(d))
			return nil
		}
		i, err := strconv.ParseInt(val, 10, getBitSize(v.Kind()))
		if err != nil {
			return parseError(v.Type().Name())
		}
		v.SetInt(i)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(val, getBitSize(v.Kind()))
		if err != nil {
			return parseError(v.Type().Name())
		}
		v.SetFloat(f)
	case reflect.Complex64, reflect.Complex128:
		c, err := strconv.ParseComplex(val, getBitSize(v.Kind()))
		if err != nil {
			return parseError(v.Type().Name())
		}
		v.SetComplex(c)
	default:
		return errors.New("unsupported type: " + v.Kind().String())
	}
	return nil
}

// getBitSize gets the bit size of the incoming numeric kind.
func getBitSize(k reflect.Kind) int {
	var bit int
	switch k {
	case reflect.Uint, reflect.Int:
		bit = strconv.IntSize
	case reflect.Uint8, reflect.Int8:
		bit = 8
	case reflect.Uint16, reflect.Int16:
		bit = 16
	case reflect.Uint32, reflect.Int32, reflect.Float32:
		bit = 32
	case reflect.Uint64, reflect.Int64, reflect.Float64, reflect.Complex64:
		bit = 64
	case reflect.Complex128:
		bit = 128
	}
	return bit
}

// isRequired checks the provided string slice if the second element (if any)
// has the same value as constant "required". If it has it returns true,
// otherwise false.
func isRequired(values []string) bool {
	if len(values) == 1 {
		return false
	}
	return values[1] == "required"
}

// parseError returns a new error with the provided type.
func parseError(typ string) error {
	return fmt.Errorf("could not parse value into type %s", typ)
}

// values contains the values of the secrets and settings. Used to
// create a common thread-safe map for the values to be used
// when setting the fields.
type values struct {
	v  map[string]string
	mu sync.RWMutex
}

// addSecrets adds the secrets to the values.
func (v *values) addSecrets(secrets map[string]Secret) {
	v.mu.Lock()
	defer v.mu.Unlock()

	for k, val := range secrets {
		v.v[k] = val.Value
	}
}

// addSettings adds the settings to the values.
func (v *values) addSettings(settings map[string]Setting) {
	v.mu.Lock()
	defer v.mu.Unlock()

	for k, val := range settings {
		v.v[k] = val.Value
	}
}

// requiredFields contains the fields and the type of the required fields.
type requiredFields struct {
	f []string
	t string
}
