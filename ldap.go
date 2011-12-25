package ldap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
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
		prompt := C.GoString(need.prompt)
		challenge := C.GoString(need.challenge)
		defresult := C.GoString(need.defresult)
		res := defresult

		if l.interact != nil {
			var err error
			res, err = l.interact(int(need.id), prompt, challenge, defresult)
			if err != nil {
				l.interactError = err
				return -1
			}
		}

		need.result = unsafe.Pointer(C.CString(res))
		need.len = C.uint(len(res))
		l.interactStrings = append(l.interactStrings, need.result)
		need = (*C.sasl_interact_t)(unsafe.Pointer(uintptr(unsafe.Pointer(need)) + unsafe.Sizeof(*need)))
	}

	return 0
}

func Dial(urlstr string, interact func(id int, prompt, challenge, defresult string) (string, error)) (*Ldap, error) {

	u, err := url.Parse(urlstr)
	if err != nil {
		return nil, err
	}

	l := &Ldap{}
	l.interact = interact

	ret := C.int(-1)
	_, addrs, _ := net.LookupSRV(u.Scheme, "tcp", u.Host)
	for _, a := range addrs {
		curl := C.CString(fmt.Sprintf("%s://%s", u.Scheme, net.JoinHostPort(a.Target, strconv.Itoa(int(a.Port)))))
		ret = C.ldap_initialize(&l.p, curl)
		C.free(unsafe.Pointer(curl))
		if ret == 0 {
			break
		}
	}

	if ret != 0 {
		curl := C.CString(urlstr)
		ret = C.ldap_initialize(&l.p, curl)
		C.free(unsafe.Pointer(curl))
	}

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

	ret = C.do_bind(l.p, C.LDAP_SASL_QUIET, unsafe.Pointer(l))

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

		if ft.PkgPath != "" {
			// private field
			continue
		}

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

		} else if ft.Type == reflect.TypeOf([][]byte{}) || ft.Type == reflect.TypeOf([]SID{}) {
			numattr++
			pv := vals
			for *pv != nil {
				s := C.GoBytes(unsafe.Pointer((*pv).bv_val), C.int((*pv).bv_len))
				fv.Set(reflect.Append(fv, reflect.ValueOf(s)))
				pv = (**C.struct_berval)(unsafe.Pointer(uintptr(unsafe.Pointer(pv)) + unsafe.Sizeof(*pv)))
			}

		} else if ft.Type == reflect.TypeOf([]byte{}) || ft.Type == reflect.TypeOf(SID{}) {
			s := C.GoBytes(unsafe.Pointer((*vals).bv_val), C.int((*vals).bv_len))
			fv.Set(reflect.ValueOf(s))

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

		msgValue := outValue

		// Ptrs to struct set the out value itself, everything else
		// use the outType to create a new instance of the structure
		if outFn != nil {
			msgValue = reflect.Indirect(reflect.New(outType))
		}

		if err := l.demarshalEntry(msg, msgValue, attrs); err == errNoData {
			continue
		} else if err != nil {
			return err
		}

		if outFn != nil {
			if err := outFn(outValue, msgValue); err != nil {
				return err
			}
		}
	}

	return nil
}

func appendSlice(out reflect.Value, value reflect.Value) error {
	out.Set(reflect.Append(out, value))
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
			maxResults = 1
			// ptr to struct sets the value directly so outFn is left as nil
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
		if f.PkgPath != "" {
			// private field
		} else if f.Name != "Dn" {
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

type SID []byte

const sidRevision = 1

func (s SID) String() string {
	ret := make([]byte, 0)
	if len(s) < 8 || s[0] != sidRevision || len(s) != (int(s[1])*4)+8 {
		return ""
	}

	ret = append(ret, "S-1-"...)
	ret = strconv.AppendUint(ret, binary.BigEndian.Uint64(s[:8])&0xFFFFFFFFFFFF, 10)

	for i := 0; i < int(s[1]); i++ {
		ret = append(ret, "-"...)
		ret = strconv.AppendUint(ret, uint64(binary.LittleEndian.Uint32(s[8+i*4:])), 10)
	}

	return string(ret)
}

func (s SID) Equal(r SID) bool {
	if len(s) != len(r) {
		return false
	}

	for i, a := range s {
		if a != r[i] {
			return false
		}
	}

	return true
}

var escapes = []string{
	"\x00", "\\00", "\x01", "\\00", "\x02", "\\02", "\x03", "\\03",
	"\x04", "\\04", "\x05", "\\05", "\x06", "\\06", "\x07", "\\07",
	"\x08", "\\08", "\x09", "\\09", "\x0A", "\\0A", "\x0B", "\\08",
	"\x0C", "\\0C", "\x0D", "\\0D", "\x0E", "\\0E", "\x0F", "\\0F",
	"\x10", "\\10", "\x11", "\\10", "\x12", "\\12", "\x13", "\\13",
	"\x14", "\\14", "\x15", "\\15", "\x16", "\\16", "\x17", "\\17",
	"\x18", "\\18", "\x19", "\\19", "\x1A", "\\1A", "\x1B", "\\18",
	"\x1C", "\\1C", "\x1D", "\\1D", "\x1E", "\\1E", "\x1F", "\\1F",
	"\x7F", "\\7F",
	"(", "\\28",
	")", "\\29",
	"&", "\\26",
	"|", "\\7c",
	"=", "\\3d",
	">", "\\3e",
	"<", "\\3c",
	"~", "\\7e",
	"*", "\\2a",
	"/", "\\2f",
	"\\", "\\5c",
}

var escaper = strings.NewReplacer(escapes...)

func Escape(v string) string {
	return escaper.Replace(v)
}
