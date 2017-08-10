package zoo

import (
	"context"
	"sync"
)

// ZooValueConstructor is a constructor for values in the zoo.
type ZooValueConstructor func() (resultObject interface{}, resultContext context.Context)

// Zoo stores arbitrary objects indexed by key.
type Zoo struct {
	dictMtx sync.Mutex
	dict    map[interface{}]interface{}
}

// NewZoo builds a new Zoo.
func NewZoo() *Zoo {
	return &Zoo{dict: make(map[interface{}]interface{})}
}

// GetOrPutData gets an existing object for a key, or creates it with the constructor.
func (z *Zoo) GetOrPutData(
	key interface{},
	valueConstructor ZooValueConstructor,
) interface{} {
	z.dictMtx.Lock()
	defer z.dictMtx.Unlock()

	obj, ok := z.dict[key]
	if !ok {
		var ctx context.Context
		obj, ctx = valueConstructor()
		if obj != nil {
			z.dict[key] = obj
			if ctx != nil {
				go func() {
					<-ctx.Done()

					z.dictMtx.Lock()
					defer z.dictMtx.Unlock()

					currObj, ok := z.dict[key]
					if !ok || currObj != obj {
						return
					}
					delete(z.dict, key)
				}()
			}
		}
	}

	return obj
}

// GetAndRemoveData removes a key and returns the removed object
func (z *Zoo) GetAndRemoveData(key interface{}) (interface{}, bool) {
	z.dictMtx.Lock()
	defer z.dictMtx.Unlock()

	obj, ok := z.dict[key]
	if ok {
		delete(z.dict, key)
	}

	return obj, ok
}

// GetData returns the object attached to the given key.
func (z *Zoo) GetData(key interface{}) (interface{}, bool) {
	z.dictMtx.Lock()
	defer z.dictMtx.Unlock()

	o, ok := z.dict[key]
	return o, ok
}
