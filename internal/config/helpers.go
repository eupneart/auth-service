package config

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type JsonResponse struct {
	Error bool `json:"error"`
	Message string `json:"message"`
	Data any `json:"data,omitempty"`
}

func (app *Config) ReadJSON(w http.ResponseWriter, r *http.Request, data any) error {
  const maxBytes = 1 << 20 // 1 MB

  r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

  dec := json.NewDecoder(r.Body)
  err := dec.Decode(data)

  if err != nil {
    return err
  }

  err = dec.Decode(&struct{}{})
  if err != io.EOF {
    return errors.New("Body must have a only single JSON value")
  }

  return nil
}

func (app *Config) WriteJSON(w http.ResponseWriter, data any, status int, header ...http.Header) error {
  // converts the payload struct into a JSON byte slice ([]byte) with pretty indentation
	out, err := json.MarshalIndent(data, "", "\t")
  if err != nil {
    return err
  }

  if len(header) > 0 {
    for key, value := range header[0] {
      w.Header()[key] = value
    }
  }
  
  // This sets the Content-Type header of the HTTP response to application/json. 
  // This tells the client (usually a browser or API consumer) that the server is sending JSON data in the response.
  w.Header().Set("Content-Type", "application/json")

  w.WriteHeader(status)
  _, err = w.Write(out)
  if err != nil {
    return err
  }
  
  return nil
}

func (app *Config) ErrorJSON(w http.ResponseWriter, err error, status ...int) {
  statusCode := http.StatusBadRequest

  if len(status) > 0 {
    statusCode = status[0]
  }

  var payload JsonResponse
  payload.Error = true
  payload.Message = err.Error()

  _ = app.WriteJSON(w, payload, statusCode)
}
