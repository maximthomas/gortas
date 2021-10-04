package state

import (
	"encoding/json"
	"fmt"
	"reflect"
)

//import "encoding/json"

type FlowState struct {
	Modules     []FlowStateModuleInfo
	SharedState map[string]string
	UserId      string
	Id          string
	RedirectURI string
	Realm       string
	Name        string
}

type FlowStateModuleInfo struct {
	Id         string
	Type       string
	Properties FlowStateModuleProperties
	Status     ModuleStatus
	State      map[string]interface{}
}

type FlowStateModuleProperties map[string]interface{}

func (mp FlowStateModuleProperties) MarshalJSON() ([]byte, error) {
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

func (f *FlowState) UpdateModuleInfo(mIndex int, mInfo FlowStateModuleInfo) {
	f.Modules[mIndex] = mInfo
}

type ModuleStatus int

const (
	FAIL ModuleStatus = -1 + iota
	START
	IN_PROGRESS //callbacks requested
	PASS
)

const (
	FlowCookieName    = "GortasAuthFlow"
	SessionCookieName = "GortasSession"
)
