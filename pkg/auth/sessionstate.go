package auth

import (
	"encoding/json"
	"fmt"
	"reflect"
)

//import "encoding/json"

type LoginSessionState struct {
	Modules     []LoginSessionStateModuleInfo
	SharedState map[string]string
	UserId      string
	SessionId   string
	RedirectURI string
}

type LoginSessionStateModuleInfo struct {
	Id          string
	Type        string
	Properties  LoginSessionStateModuleProperties
	State       ModuleState
	SharedState map[string]string
}

type LoginSessionStateModuleProperties map[string]interface{}

func (mp LoginSessionStateModuleProperties) MarshalJSON() ([]byte, error) {
	var cp = make(map[string]interface{})
	for k, v := range mp {
		cp[k] = convertInterface(v)
	}
	return json.Marshal(cp)
}

func convertInterface(v interface{}) interface{} {
	var res interface{}
	switch v.(type) {
	case []map[interface{}]interface{}:
		rVal := reflect.ValueOf(v)
		mMaps := make([]map[string]string, rVal.Len())
		for i := 0; i < rVal.Len(); i++ {
			mMap := make(map[string]string)
			iter := rVal.Index(i).MapRange()
			for iter.Next() {
				mk := fmt.Sprintf("%v", iter.Key())
				mv := fmt.Sprintf("%v", iter.Value())
				mMap[mk] = mv
			}
			mMaps[i] = mMap
		}
		res = mMaps
	case map[interface{}]interface{}:
		rVal := reflect.ValueOf(v)
		mMap := make(map[string]string)
		iter := rVal.MapRange()
		for iter.Next() {
			k := fmt.Sprintf("%v", iter.Key())
			v := fmt.Sprintf("%v", iter.Value())
			mMap[k] = v
		}
		res = mMap
	case []interface{}:
		rVal := reflect.ValueOf(v)
		ar := make([]interface{}, rVal.Len())
		for i := 0; i < rVal.Len(); i++ {
			ar[i] = convertInterface(rVal.Index(i).Interface())
		}
		res = ar
	default:
		res = v
	}
	return res
}

func (l *LoginSessionState) UpdateModuleInfo(mIndex int, mInfo LoginSessionStateModuleInfo) {
	l.Modules[mIndex] = mInfo
}

type ModuleState int

const (
	Fail ModuleState = -1 + iota
	Start
	InProgress //callbacks requested
	Pass
)

const (
	AuthCookieName    = "GortasAuthSession"
	SessionCookieName = "GortasSession"
)
