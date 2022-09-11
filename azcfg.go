package azcfg

import (
	"errors"
	"reflect"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/KarlGW/azcfg/internal/pkg/keyvault"
)

const (
	defaultTag = "secret"
)

// Parse secrets from an Azure Key Vault into a struct.
func Parse(v any) error {
	var err error
	var cred azcore.TokenCredential
	if opts.Credential != nil {
		cred = opts.Credential
	} else {
		cred, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return err
		}
	}

	var vault string
	if len(opts.Vault) != 0 {
		vault = opts.Vault
	} else {
		vault, err = getVaultFromEnvironment()
		if err != nil {
			return err
		}
	}

	return parse(v, keyvault.NewClient(vault, cred, nil))
}

// keyvaultClient is the interface that wrap arounds method GetSecrets.
type keyvaultClient interface {
	GetSecrets(names []string) (map[string]string, error)
}

// Parse secrets into the configuration.
func parse(d any, client keyvaultClient) error {
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

	setFields(v, secrets)
	return nil
}

// getFieldsWithTag gets fields with the specified tag.
func getFields(v reflect.Value, tag string) []string {
	t := v.Type()
	fields := make([]string, 0)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Pointer && v.Field(i).Elem().Kind() == reflect.Struct {
			fields = append(fields, getFields(v.Field(i).Elem(), tag)...)
		} else if v.Field(i).Kind() == reflect.Struct {
			fields = append(fields, getFields(v.Field(i), tag)...)
		} else {
			tagValue := t.Field(i).Tag.Get(tag)
			if len(tagValue) > 0 {
				fields = append(fields, tagValue)
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
		if v.Field(i).Kind() == reflect.Pointer && v.Field(i).Elem().Kind() == reflect.Struct {
			setFields(v.Field(i).Elem(), secrets)
		} else if v.Field(i).Kind() == reflect.Struct {
			setFields(v.Field(i), secrets)
		} else {
			tagValue := t.Field(i).Tag.Get(defaultTag)
			if len(tagValue) == 0 {
				continue
			}
			if val, ok := secrets[tagValue]; ok {
				if err := setValue(v.Field(i), val); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// setValue sets the new value on the incoming reflect.Value.
func setValue(v reflect.Value, val string) error {
	// TODO:
	// Support more types.
	switch v.Kind() {
	case reflect.Pointer:
		v = v.Elem()
		setValue(v, val)
	case reflect.String:
		v.SetString(val)
	case reflect.Bool:
		b, err := strconv.ParseBool(val)
		if err != nil {
			b = false
		}
		v.SetBool(b)
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
	case reflect.Int:
		// TODO:
		// Handle based on OS ARCH, revisit and update.
		bit = 32
	case reflect.Int8:
		bit = 8
	case reflect.Int16:
		bit = 16
	case reflect.Int32, reflect.Float32:
		bit = 32
	case reflect.Int64, reflect.Float64:
		bit = 64
	}
	return bit
}
