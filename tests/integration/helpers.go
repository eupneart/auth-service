package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// MakeRequest is a helper to make HTTP requests in tests
func MakeRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
	var requestBody []byte
	if body != nil {
		var err error
		requestBody, err = json.Marshal(body)
		require.NoError(t, err)
	}

	req, err := http.NewRequest(method, path, bytes.NewReader(requestBody))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	return w
}

// ParseResponse is a helper to parse JSON response
func ParseResponse(t *testing.T, body []byte, v interface{}) {
	err := json.Unmarshal(body, v)
	require.NoError(t, err)
}

// AssertStatusCode asserts the HTTP status code
func AssertStatusCode(t *testing.T, resp *httptest.ResponseRecorder, expectedStatus int) {
	require.Equal(t, expectedStatus, resp.Code, "expected status code %d but got %d", expectedStatus, resp.Code)
}

// AssertResponseError asserts that response contains an error
func AssertResponseError(t *testing.T, resp *httptest.ResponseRecorder) {
	var data map[string]interface{}
	ParseResponse(t, resp.Body.Bytes(), &data)

	hasError, ok := data["error"].(bool)
	require.True(t, ok, "response should have 'error' field")
	require.True(t, hasError, "response should indicate an error")
}

// AssertResponseSuccess asserts that response is successful
func AssertResponseSuccess(t *testing.T, resp *httptest.ResponseRecorder) {
	var data map[string]interface{}
	ParseResponse(t, resp.Body.Bytes(), &data)

	hasError, ok := data["error"].(bool)
	require.True(t, ok, "response should have 'error' field")
	require.False(t, hasError, "response should not indicate an error")
}
