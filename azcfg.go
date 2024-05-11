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
	secretTag   = "secret"
	settingTag  = "setting"
	requiredTag = "required"
)

// Parse secrets from an Azure Key Vault and settings from an
// Azure App Configuration into the provided struct.
func Parse(ctx context.Context, v any, options ...Option) error {
	parser, err := NewParser(options...)
	if err != nil {
		return err
	}
	return parser.Parse(ctx, v)
}

// parseOptions contains options for the parser.
type parseOptions struct {
	secretClient  secretClient
	settingClient settingClient
}

// Parse secrets into the configuration.
func parse(ctx context.Context, d any, opts parseOptions) error {
	v := reflect.ValueOf(d)
	if v.Kind() != reflect.Pointer {
		return errors.New("must provide a pointer to a struct")
	}
	v = reflect.ValueOf(d).Elem()
	if v.Kind() != reflect.Struct {
		return errors.New("provided value is not a struct")
	}

	var wg sync.WaitGroup
	secretsCh := make(chan map[string]Secret)
	settingsCh := make(chan map[string]Setting)
	errCh := make(chan error)
	done := make(chan struct{})

	secretClient := opts.secretClient
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
			secretsCh <- secrets
		}()
	}

	settingClient := opts.settingClient
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
			settingsCh <- settings
		}()
	}

	go func() {
		wg.Wait()
		done <- struct{}{}
		close(done)
		close(errCh)
		close(secretsCh)
		close(settingsCh)
	}()

	var errs []error
	for {
		select {
		case s := <-secretsCh:
			secrets := s
			if len(secrets) > 0 {
				if err := setFields(v, secrets, secretTag); err != nil {
					if errors.Is(err, errRequired) {
						err = requiredSecretsError{message: requiredErrorMessage(secrets, requiredSecrets, "secret")}
					}
					errs = append(errs, err)
				}
			}
		case s := <-settingsCh:
			settings := s
			if len(settings) > 0 {
				if err := setFields(v, settings, settingTag); err != nil {
					if errors.Is(err, errRequired) {
						err = requiredSettingsError{message: requiredErrorMessage(settings, requiredSettings, "setting")}
					}
					errs = append(errs, err)
				}
			}
		case err := <-errCh:
			if err != nil {
				errs = append(errs, err)
			}
		case <-done:
			if len(errs) > 0 {
				return buildErr(errs...)
			}
			return nil
		}
	}
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

// setFields sets the values from the map into the struct fields.
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
					return errRequired
				} else if len(val.GetValue()) == 0 {
					continue
				}
				if v.Field(i).Kind() == reflect.Slice {
					vals := splitTrim(val.GetValue(), ",")
					sl := reflect.MakeSlice(v.Field(i).Type(), len(vals), len(vals))
					for j := 0; j < sl.Cap(); j++ {
						if err := setValue(sl.Index(j), vals[j]); err != nil {
							return fmt.Errorf("%w: field %s: %s", ErrSetValue, t.Field(i).Name, err.Error())
						}
					}
					v.Field(i).Set(sl)
				} else {
					if err := setValue(v.Field(i), val.GetValue()); err != nil {
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
	return values[1] == requiredTag
}

// parseError returns a new error with the provided type.
func parseError(typ string) error {
	return fmt.Errorf("could not parse value into type %s", typ)
}
