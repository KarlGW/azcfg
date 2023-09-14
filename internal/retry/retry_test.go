package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDo(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			ctx     func() context.Context
			fn      func(i *int) func() error
			options []PolicyOption
		}
		wantRetries int
		wantErr     error
	}{
		{
			name: "successfull call",
			input: struct {
				ctx     func() context.Context
				fn      func(i *int) func() error
				options []PolicyOption
			}{
				ctx: func() context.Context {
					return context.Background()
				},
				fn: func(i *int) func() error {
					return func() error {
						*i++
						return nil
					}
				},
			},
			wantRetries: 0,
			wantErr:     nil,
		},
		{
			name: "successfull call 2 retries",
			input: struct {
				ctx     func() context.Context
				fn      func(i *int) func() error
				options []PolicyOption
			}{
				ctx: func() context.Context {
					return context.Background()
				},
				fn: func(i *int) func() error {
					return func() error {
						*i++
						if *i < 2 {
							return errors.New("error")
						}
						return nil
					}
				},
				options: []PolicyOption{
					func(o *Policy) {
						o.MinDelay = time.Millisecond * 1
						o.MaxDelay = time.Millisecond * 5
					},
				},
			},
			wantRetries: 2,
			wantErr:     nil,
		},
		{
			name: "failure call 3 retries",
			input: struct {
				ctx     func() context.Context
				fn      func(i *int) func() error
				options []PolicyOption
			}{
				ctx: func() context.Context {
					return context.Background()
				},
				fn: func(i *int) func() error {
					return func() error {
						*i++
						if *i <= 4 {
							return errors.New("error")
						}
						return nil
					}
				},
				options: []PolicyOption{
					func(o *Policy) {
						o.MinDelay = time.Millisecond * 1
						o.MaxDelay = time.Millisecond * 5
					},
				},
			},
			wantRetries: 3,
			wantErr:     nil,
		},
		{
			name: "failure call context deadline",
			input: struct {
				ctx     func() context.Context
				fn      func(i *int) func() error
				options []PolicyOption
			}{
				ctx: func() context.Context {
					ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*1)
					defer cancel()
					return ctx
				},
				fn: func(i *int) func() error {
					return func() error {
						*i++
						if *i <= 4 {
							return errors.New("error")
						}
						return nil
					}
				},
				options: []PolicyOption{
					func(o *Policy) {
						o.MinDelay = time.Millisecond * 5
						o.MaxDelay = time.Millisecond * 10
					},
				},
			},
			wantRetries: 0,
			wantErr:     errors.New("context deadline"),
		},
		{
			name: "should not retry",
			input: struct {
				ctx     func() context.Context
				fn      func(i *int) func() error
				options []PolicyOption
			}{
				ctx: func() context.Context {
					return context.Background()
				},
				fn: func(i *int) func() error {
					return func() error {
						*i++
						if *i < 1 {
							return errDoNotRetry
						}
						if *i <= 4 {
							return errors.New("error")
						}
						return nil
					}
				},
				options: []PolicyOption{
					func(o *Policy) {
						o.MinDelay = time.Millisecond * 1
						o.MaxDelay = time.Millisecond * 5
						o.Retry = func(err error) bool {
							return !errors.Is(err, errDoNotRetry)
						}
					},
				},
			},
			wantRetries: 0,
			wantErr:     errDoNotRetry,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotRetries := -1
			gotErr := Do(test.input.ctx(), test.input.fn(&gotRetries), test.input.options...)

			if test.wantErr != nil && gotErr == nil {
				t.Errorf("Do() = unexpected error, want: %v, got: %v\n", test.wantErr, gotErr)
			}

			if test.wantRetries != gotRetries {
				t.Errorf("Do() = unexpected result, want: %v, got: %v\n", test.wantRetries, gotRetries)
			}
		})
	}
}

var (
	errDoNotRetry = errors.New("do not retry")
)
