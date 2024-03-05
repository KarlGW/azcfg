package azcfg

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/KarlGW/azcfg/internal/setting"
)

const (
	secretTag   = "secret"
	settingTag  = "setting"
	requiredTag = "required"
)

// Parse secrets from an Azure Key Vault into a struct.
func Parse(v any, options ...Option) error {
	parser, err := NewParser(options...)
	if err != nil {
		return err
	}
	return parser.Parse(v)
}

// Parse secrets into the configuration.
func parse(d any, secretClient secretClient, settingClient settingClient, label string) error {
	v := reflect.ValueOf(d)
	if v.Kind() != reflect.Pointer {
		return errors.New("must provide a pointer to a struct")
	}
	v = reflect.ValueOf(d).Elem()
	if v.Kind() != reflect.Struct {
		return errors.New("provided value is not a struct")
	}

	errCh := make(chan error, 2)
	mu := sync.RWMutex{}
	var wg sync.WaitGroup

	secretFields, requiredSecrets := getFields(v, secretTag)
	if len(secretFields) > 0 && secretClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			secrets, err := secretClient.GetSecrets(secretFields)
			if err != nil {
				errCh <- err
				return
			}

			mu.Lock()
			defer mu.Unlock()

			if err := setFields(v, secrets, secretTag); err != nil {
				if errors.Is(err, errRequired) {
					errCh <- requiredSecretsError{message: requiredErrorMessage(secrets, requiredSecrets, "secret")}
					return
				}
				errCh <- err
				return
			}
		}()
	}

	settingFields, requiredSettings := getFields(v, settingTag)
	if len(settingFields) > 0 && settingClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			settings, err := settingClient.GetSettings(settingFields, setting.WithLabel(label))
			if err != nil {
				errCh <- err
				return
			}

			mu.Lock()
			defer mu.Unlock()

			if err := setFields(v, settings, settingTag); err != nil {
				if errors.Is(err, errRequired) {
					errCh <- requiredSettingsError{message: requiredErrorMessage(settings, requiredSettings, "setting")}
					return
				}
				errCh <- err
				return
			}
		}()
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	var errs []error
	for err := range errCh {
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return buildErr(errs...)
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

// hasValue wraps around method GetValue,
type hasValue interface {
	GetValue() string
}

func setFields[V hasValue](v reflect.Value, values map[string]V, tag string) error {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).CanSet() {
			continue
		}
		if v.Field(i).Kind() == reflect.Pointer && v.Field(i).Elem().Kind() == reflect.Struct {
			if err := setFields(v.Field(i).Elem(), values, tag); err != nil {
				return err
			}
		} else if v.Field(i).Kind() == reflect.Struct {
			if err := setFields(v.Field(i), values, tag); err != nil {
				return err
			}
		} else {
			value, ok := t.Field(i).Tag.Lookup(tag)
			if !ok {
				continue
			}
			tags := strings.Split(value, ",")
			if val, ok := values[tags[0]]; ok {
				if len(val.GetValue()) == 0 && isRequired(tags) {
					return fmt.Errorf("%w: %s", errRequired, tags[0])
				} else if len(val.GetValue()) == 0 {
					continue
				}
				if v.Field(i).Kind() == reflect.Slice {
					vals := splitTrim(val.GetValue(), ",")
					sl := reflect.MakeSlice(v.Field(i).Type(), len(vals), len(vals))
					for j := 0; j < sl.Cap(); j++ {
						if err := setValue(sl.Index(j), vals[j]); err != nil {
							return err
						}
					}
					v.Field(i).Set(sl)
				} else {
					if err := setValue(v.Field(i), val.GetValue()); err != nil {
						return err
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
		setValue(v.Elem(), val)
	case reflect.String:
		v.SetString(val)
	case reflect.Bool:
		b, err := strconv.ParseBool(val)
		if err != nil {
			b = false
		}
		v.SetBool(b)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i, err := strconv.ParseUint(val, 10, getBitSize(v.Kind()))
		if err != nil {
			return err
		}
		v.SetUint(i)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.ParseInt(val, 10, getBitSize(v.Kind()))
		if err != nil {
			return err
		}
		v.SetInt(i)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(val, getBitSize(v.Kind()))
		if err != nil {
			return err
		}
		v.SetFloat(f)
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
	case reflect.Uint64, reflect.Int64, reflect.Float64:
		bit = 64
	}
	return bit
}

// splitTrim splits a string by the provided separator, after
// trimming whitespaces.
func splitTrim(s, sep string) []string {
	if len(s) == 0 {
		return nil
	}
	if len(sep) == 0 {
		sep = ","
	}
	return strings.Split(regexp.MustCompile(sep+`\s+`).ReplaceAllString(s, sep), sep)
}

// isRequired checks the provided string slice if the second element (if any)
// has the same value as constant "required". If it has it returns true,
// otherwise false.
func isRequired(values []string) bool {
	if len(values) == 1 {
		return false
	}
	return values[1] == requiredTag
}
