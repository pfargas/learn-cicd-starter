package auth

import (
	"net/http"
	"testing"
	"errors"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		headers 	 http.Header
		expectedKey  string
		expectedError error
	}
	
	tests := []test{
		{
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey:  "my-secret-key",
			expectedError: nil,
		},
		{
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			expectedKey:  "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:  "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			headers: http.Header{},
			expectedKey:  "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			headers : http.Header{
				"authorization": []string{"ApiKey another-key"},
			},
			expectedKey: "",
			expectedError: ErrNoAuthHeaderIncluded, // Header keys are case-sensitive
		},
	}

	for _, tc := range tests {
		key, err := GetAPIKey(tc.headers)
		
		if key != tc.expectedKey {
			t.Errorf("expected key %s, got %s", tc.expectedKey, key)
		}
		
		if (err == nil) != (tc.expectedError == nil) || (err != nil && err.Error() != tc.expectedError.Error()) {
			t.Errorf("expected error %v, got %v", tc.expectedError, err)
		}
	}	
}