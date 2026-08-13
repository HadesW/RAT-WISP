package services

import (
	"encoding/json"
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

// luaToJSON marshals an arbitrary Lua value to JSON text.
func luaToJSON(v lua.LValue) string {
	var b []byte
	switch val := v.(type) {
	case lua.LString:
		b, _ = json.Marshal(string(val))
	case lua.LNumber:
		b, _ = json.Marshal(float64(val))
	case lua.LBool:
		b, _ = json.Marshal(bool(val))
	case *lua.LTable:
		b = tableToJSON(val)
	default:
		b, _ = json.Marshal(val.String())
	}
	return string(b)
}

// tableToJSON converts a Lua table to JSON, detecting array vs object form.
func tableToJSON(t *lua.LTable) []byte {
	// Array form: 1..N consecutive integer keys.
	n := t.Len()
	if n > 0 {
		arr := make([]any, 0, n)
		for i := 1; i <= n; i++ {
			arr = append(arr, luaToGo(t.RawGetInt(i)))
		}
		b, _ := json.Marshal(arr)
		return b
	}
	m := map[string]any{}
	t.ForEach(func(k, v lua.LValue) {
		m[k.String()] = luaToGo(v)
	})
	b, _ := json.Marshal(m)
	return b
}

// luaToGo converts a Lua value to a Go value suitable for JSON.
func luaToGo(v lua.LValue) any {
	switch val := v.(type) {
	case lua.LString:
		return string(val)
	case lua.LNumber:
		return float64(val)
	case lua.LBool:
		return bool(val)
	case *lua.LTable:
		n := val.Len()
		if n > 0 {
			arr := make([]any, 0, n)
			for i := 1; i <= n; i++ {
				arr = append(arr, luaToGo(val.RawGetInt(i)))
			}
			return arr
		}
		m := map[string]any{}
		val.ForEach(func(k, v lua.LValue) {
			m[k.String()] = luaToGo(v)
		})
		return m
	default:
		return v.String()
	}
}

// anyToLua converts a Go value (from server events) into a Lua value.
func anyToLua(L *lua.LState, v any) lua.LValue {
	switch val := v.(type) {
	case nil:
		return lua.LNil
	case string:
		return lua.LString(val)
	case bool:
		return lua.LBool(val)
	case int:
		return lua.LNumber(val)
	case int64:
		return lua.LNumber(val)
	case float64:
		return lua.LNumber(val)
	case map[string]string:
		t := L.NewTable()
		for k, vv := range val {
			t.RawSetString(k, lua.LString(vv))
		}
		return t
	case map[string]any:
		t := L.NewTable()
		for k, vv := range val {
			t.RawSetString(k, anyToLua(L, vv))
		}
		return t
	case []any:
		t := L.NewTable()
		for i, vv := range val {
			t.RawSetInt(i+1, anyToLua(L, vv))
		}
		return t
	default:
		// Last resort: marshal to JSON and parse back into a Lua table.
		b, err := json.Marshal(v)
		if err != nil {
			return lua.LString(fmt.Sprintf("%v", v))
		}
		var out lua.LValue
		L.SetTop(0)
		if err := L.DoString("return " + string(b)); err != nil {
			return lua.LString(string(b))
		}
		out = L.Get(-1)
		L.Pop(1)
		return out
	}
}
