package azcfg

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/KarlGW/azcfg/internal/keyvault"
)

const (
	defaultTag = "secret"
	required   = "required"
)

// Parse secrets from an Azure Key Vault into a struct.
func Parse(v any, o ...Options) error {
	client, err := evalClient(
		evalOptions(o...),
		newAzureCredential,
		newKeyvaultClient,
	)
	if err != nil {
		return err
	}

	return parse(v, client)
}

// Parse secrets into the configuration.
func parse(d any, client SecretsClient) error {
	v := reflect.ValueOf(d)
	if v.Kind() != reflect.Pointer {
		return errors.New("must provide a pointer to a struct")
	}
	v = reflect.ValueOf(d).Elem()
	if v.Kind() != reflect.Struct {
		return errors.New("provided value is not a struct")
	}

	secrets, err := client.GetSecrets(getFields(v, defaultTag))
	if err != nil {
		return err
	}

	return setFields(v, secrets)
}

// getFields gets fields with the specified tag.
func getFields(v reflect.Value, tag string) []string {
	t := v.Type()
	fields := make([]string, 0)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Pointer && v.Field(i).Elem().Kind() == reflect.Struct {
			fields = append(fields, getFields(v.Field(i).Elem(), tag)...)
		} else if v.Field(i).Kind() == reflect.Struct {
			fields = append(fields, getFields(v.Field(i), tag)...)
		} else {
			if tagValue, ok := t.Field(i).Tag.Lookup(tag); ok {
				fields = append(fields, strings.Split(tagValue, ",")[0])
			}
		}
	}
	return fields
}

// setFields takes incoming map of values and sets them with the
// value with the map key/struct tag match.
func setFields(v reflect.Value, secrets map[string]string) error {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).CanSet() {
			continue
		}
		if v.Field(i).Kind() == reflect.Pointer && v.Field(i).Elem().Kind() == reflect.Struct {
			if err := setFields(v.Field(i).Elem(), secrets); err != nil {
				return err
			}
		} else if v.Field(i).Kind() == reflect.Struct {
			if err := setFields(v.Field(i), secrets); err != nil {
				return err
			}
		} else {
			tagValue, ok := t.Field(i).Tag.Lookup(defaultTag)
			if !ok {
				continue
			}
			tagValues := strings.Split(tagValue, ",")
			if val, ok := secrets[tagValues[0]]; ok {
				if len(val) == 0 && isRequired(tagValues) {
					return fmt.Errorf("secret: %q marked as required", tagValues[0])
				} else if len(val) == 0 {
					continue
				}
				if v.Field(i).Kind() == reflect.Slice {
					vals := splitTrim(val, ",")
					sl := reflect.MakeSlice(v.Field(i).Type(), len(vals), len(vals))
					for j := 0; j < sl.Cap(); j++ {
						if err := setValue(sl.Index(j), vals[j]); err != nil {
							return err
						}
					}
					v.Field(i).Set(sl)
				} else {
					if err := setValue(v.Field(i), val); err != nil {
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
	return values[1] == required
}

// newAzureCredential calls azidentity.NewDefaultAzureCredential.
func newAzureCredential() (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}

// newKeyVaultClient calls keyvault.NewClient.
func newKeyvaultClient(vault string, cred azcore.TokenCredential, options *keyvault.ClientOptions) (SecretsClient, error) {
	return keyvault.NewClient(vault, cred, options)
}
