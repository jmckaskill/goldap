package ldap

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"unsafe"
)

/*
#cgo LDFLAGS: -lldap
#include <ldap.h>
#include <sasl/sasl.h>
#include <limits.h>
#include <stdlib.h>
#include <ctype.h>
extern int c_interact(LDAP* ld, unsigned flags, void* defaults, void* interact);
static int do_bind(LDAP* ld, unsigned flags, void* defaults) {
	return ldap_sasl_interactive_bind_s(ld, NULL, NULL, NULL, NULL, flags, &c_interact, defaults);
}
static void first_tolower(char* str) {
	str[0] = tolower(str[0]);
}
*/
import "C"

var (
	Realm        = C.SASL_CB_GETREALM
	AuthName     = C.SASL_CB_AUTHNAME
	Password     = C.SASL_CB_PASS
	UserName     = C.SASL_CB_USER
	NoEchoPrompt = C.SASL_CB_NOECHOPROMPT
	EchoPrompt   = C.SASL_CB_ECHOPROMPT
)

type ErrLdap int

func (s ErrLdap) Error() string {
	return "ldap: " + C.GoString(C.ldap_err2string(C.int(s)))
}

type ErrUnsupportedType struct {
	t reflect.Type
}

func (s ErrUnsupportedType) Error() string {
	return fmt.Sprintf("ldap: unsupported type %s", s.t)
}

type Ldap struct {
	p               *C.LDAP
	interactStrings []unsafe.Pointer
	interactError   error
	interact        func(id int, prompt, challenge, defresult string) (string, error)
}

//export c_interact
func c_interact(ldp unsafe.Pointer, flags C.uint, lp unsafe.Pointer, needp unsafe.Pointer) int {
	l := (*Ldap)(lp)
	need := (*C.sasl_interact_t)(needp)
	for need.id != C.SASL_CB_LIST_END {
		if l.interact != nil {
			prompt := C.GoString(need.prompt)
			challenge := C.GoString(need.challenge)
			defresult := C.GoString(need.defresult)

			res, err := l.interact(int(need.id), prompt, challenge, defresult)
			if err != nil {
				l.interactError = err
				return -1
			}

			need.result = unsafe.Pointer(C.CString(res))
			need.len = C.uint(len(res))
			l.interactStrings = append(l.interactStrings, need.result)
		}
		need = (*C.sasl_interact_t)(unsafe.Pointer(uintptr(unsafe.Pointer(need)) + unsafe.Sizeof(*need)))
	}

	return 0
}

func Dial(url string, interact func(id int, prompt, challenge, defresult string) (string, error)) (*Ldap, error) {

	l := &Ldap{}
	l.interact = interact

	urlstr := C.CString(url)
	defer C.free(unsafe.Pointer(urlstr))

	ret := C.ldap_initialize(&l.p, urlstr)
	if ret != 0 {
		return nil, ErrLdap(ret)
	}

	runtime.SetFinalizer(l, do_close)

	version := C.int(3)
	ret = C.ldap_set_option(l.p, C.LDAP_OPT_PROTOCOL_VERSION, unsafe.Pointer(&version))
	if ret != 0 {
		return nil, ErrLdap(ret)
	}

	defer func() {
		for _, str := range l.interactStrings {
			C.free(str)
		}
		l.interactStrings = nil
	}()

	ret = C.do_bind(l.p, C.LDAP_SASL_AUTOMATIC, unsafe.Pointer(l))

	if l.interactError != nil {
		l.Close()
		return nil, l.interactError
	}

	if ret != 0 {
		return nil, ErrLdap(ret)
	}

	return l, nil
}

func do_close(l *Ldap) {
	if l.p != nil {
		C.ldap_unbind_ext_s(l.p, nil, nil)
		l.p = nil
	}
}

func (l *Ldap) Close() {
	do_close(l)
}

func setInt(fv reflect.Value, s string, bitSize int) error {
	v, err := strconv.ParseInt(s, 10, bitSize)
	if err != nil {
		return err
	}
	fv.SetInt(v)
	return nil
}

func setUint(fv reflect.Value, s string, bitSize int) error {
	v, err := strconv.ParseUint(s, 10, bitSize)
	if err != nil {
		return err
	}
	fv.SetUint(v)
	return nil
}

var errNoData = errors.New("no data")

func (l *Ldap) demarshalEntry(msg *C.LDAPMessage, msgValue reflect.Value, attrs []*C.char) error {
	numattr := 0

	for i, j := 0, 0; i < msgValue.NumField(); i++ {
		ft := msgValue.Type().Field(i)
		fv := msgValue.Field(i)

		if ft.Name == "Dn" {
			dnp := C.ldap_get_dn(l.p, msg)
			dn := C.GoString(dnp)
			C.ldap_memfree(unsafe.Pointer(dnp))

			switch ft.Type {
			case reflect.TypeOf(""):
				fv.SetString(dn)
			case reflect.TypeOf([]byte{}):
				fv.Set(reflect.ValueOf([]byte(dn)))
			default:
				return ErrUnsupportedType{ft.Type}
			}

			continue
		}

		var err error
		vals := C.ldap_get_values_len(l.p, msg, attrs[j])
		j++

		if vals == nil || *vals == nil {

		} else if ft.Type == reflect.TypeOf([]string{}) {
			numattr++
			pv := vals
			for *pv != nil {
				s := C.GoStringN((*pv).bv_val, C.int((*pv).bv_len))
				fv.Set(reflect.Append(fv, reflect.ValueOf(s)))
				pv = (**C.struct_berval)(unsafe.Pointer(uintptr(unsafe.Pointer(pv)) + unsafe.Sizeof(*pv)))
			}

		} else if ft.Type == reflect.TypeOf([][]byte{}) {
			numattr++
			pv := vals
			for *pv != nil {
				s := C.GoBytes(unsafe.Pointer((*pv).bv_val), C.int((*pv).bv_len))
				fv.Set(reflect.Append(fv, reflect.ValueOf(s)))
				pv = (**C.struct_berval)(unsafe.Pointer(uintptr(unsafe.Pointer(pv)) + unsafe.Sizeof(*pv)))
			}

		} else {
			numattr++
			s := C.GoStringN((*vals).bv_val, C.int((*vals).bv_len))

			switch ft.Type.Kind() {
			case reflect.String:
				fv.SetString(s)

			case reflect.Int8:
				err = setInt(fv, s, 8)
			case reflect.Int16:
				err = setInt(fv, s, 16)
			case reflect.Int32:
				err = setInt(fv, s, 32)
			case reflect.Int64:
				err = setInt(fv, s, 64)
			case reflect.Int:
				err = setInt(fv, s, 0)

			case reflect.Uint8:
				err = setUint(fv, s, 8)
			case reflect.Uint16:
				err = setUint(fv, s, 16)
			case reflect.Uint32:
				err = setUint(fv, s, 32)
			case reflect.Uint64:
				err = setUint(fv, s, 64)
			case reflect.Uint:
				err = setUint(fv, s, 0)

			default:
				err = ErrUnsupportedType{ft.Type}
			}
		}

		C.ldap_memvfree((*unsafe.Pointer)(unsafe.Pointer(vals)))

		if err != nil {
			return err
		}
	}

	if numattr == 0 {
		return errNoData
	}

	return nil
}

func (l *Ldap) demarshalEntryMessage(first *C.LDAPMessage, outFn func(reflect.Value, reflect.Value) error, outValue reflect.Value, outType reflect.Type, attrs []*C.char) error {

	for msg := C.ldap_first_entry(l.p, first); msg != nil; msg = C.ldap_next_entry(l.p, msg) {

		msgValue := reflect.Indirect(reflect.New(outType))

		if err := l.demarshalEntry(msg, msgValue, attrs); err == errNoData {
			continue
		} else if err != nil {
			return err
		}

		if err := outFn(outValue, msgValue); err != nil {
			return err
		}
	}

	return nil
}

func appendSlice(out reflect.Value, value reflect.Value) error {
	out.Set(reflect.Append(out, value))
	return nil
}

func setStruct(out reflect.Value, value reflect.Value) error {
	out.Set(value)
	return nil
}

func call(out reflect.Value, value reflect.Value) error {
	args := [1]reflect.Value{value}
	rets := out.Call(args[:])

	if err, ok := rets[0].Interface().(error); ok {
		return err
	}

	return nil
}

func send(out reflect.Value, value reflect.Value) error {
	out.Send(value)
	return nil
}

func (l *Ldap) SearchTree(base, filter string, out interface{}) error {
	var outFn func(out, value reflect.Value) error
	var outType reflect.Type
	maxResults := C.int(0)

	if filter == "" {
		filter = "(objectClass=*)"
	}

	outValue := reflect.ValueOf(out)
	switch outValue.Kind() {
	case reflect.Ptr:
		outValue = reflect.Indirect(outValue)

		switch outValue.Kind() {
		case reflect.Slice:
			outType = outValue.Type().Elem()
			outFn = appendSlice
		case reflect.Struct:
			outType = outValue.Type()
			outFn = setStruct
			maxResults = 1
		}

	case reflect.Func:
		ft := outValue.Type()
		if ft.NumIn() != 1 {
			panic("expected function with 1 argument")
		}

		outType = ft.In(1)
		outFn = call

	case reflect.Chan:
		outType = outValue.Type().Elem()
		outFn = send

	default:
		return ErrUnsupportedType{outValue.Type()}
	}

	if outType.Kind() != reflect.Struct {
		return ErrUnsupportedType{outValue.Type()}
	}

	attrs := make([]*C.char, 0, outType.NumField())
	for i := 0; i < outType.NumField(); i++ {
		f := outType.Field(i)
		if f.Name != "Dn" {
			attr := C.CString(f.Name)
			// Go requires the first letter to be upper case in
			// order for the field to be reflected, but ldap uses
			// lower cases camel by default
			C.first_tolower(attr)
			attrs = append(attrs, attr)
		}
	}
	attrs = append(attrs, nil)

	bstr := C.CString(base)
	fstr := C.CString(filter)

	defer func() {
		for _, str := range attrs {
			C.free(unsafe.Pointer(str))
		}

		C.free(unsafe.Pointer(bstr))
		C.free(unsafe.Pointer(fstr))
	}()

	var id C.int
	ret := C.ldap_search_ext(l.p, bstr, C.LDAP_SCOPE_SUBTREE, fstr, &attrs[0], 0, nil, nil, nil, maxResults, &id)

	if ret != 0 {
		return ErrLdap(ret)
	}

	for {
		var msg *C.LDAPMessage
		ret := C.ldap_result(l.p, id, 0, nil, &msg)

		if ret < 0 {
			return ErrLdap(ret)
		}

		var err error

		switch ret {
		case C.LDAP_RES_SEARCH_ENTRY:
			err = l.demarshalEntryMessage(msg, outFn, outValue, outType, attrs)
		}

		C.ldap_msgfree(msg)

		if err != nil {
			return err
		}

		if ret == C.LDAP_RES_SEARCH_RESULT || ret == 0 {
			break
		}
	}

	return nil
}
