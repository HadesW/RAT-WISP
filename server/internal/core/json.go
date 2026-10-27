package core

import "encoding/json"

func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }
