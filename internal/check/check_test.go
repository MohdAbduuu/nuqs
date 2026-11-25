// Tests when checks apply and how check lists are validated.

package check

import (
	"context"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/internal/model"
)

type stub struct{ info Info }

func (s stub) Info() Info                                   { return s.info }
func (s stub) Run(context.Context, Target) (*Result, error) { return nil, nil }

func good(id string) stub {
	return stub{Info{
		ID:          id,
		Title:       "t",
		Description: "plain-words description",
		Fix:         "f",
		Severity:    model.Low,
		Ports:       []int{80},
		Services:    []string{"http"},
		References:  []Reference{{Title: "Example", URL: "https://example.com/ref"}},
	}}
}

func TestApplies(t *testing.T) {
	http80 := model.Service{Port: 80, Protocol: "tcp", Name: "http"}
	http8080 := model.Service{Port: 8080, Protocol: "tcp", Name: "HTTP"}
	ssh := model.Service{Port: 22, Protocol: "tcp", Name: "ssh"}

	cases := []struct {
		name string
		info Info
		svc  model.Service
		want bool
	}{
		{"empty matches all", Info{}, ssh, true},
		{"port match", Info{Ports: []int{80}}, http80, true},
		{"port miss", Info{Ports: []int{80}}, ssh, false},
		{"service match", Info{Services: []string{"http"}}, http80, true},
		{"service match ignores case", Info{Services: []string{"http"}}, http8080, true},
		{"service miss", Info{Services: []string{"http"}}, ssh, false},
		{"port OR service", Info{Ports: []int{21}, Services: []string{"http"}}, http8080, true},
		{"neither", Info{Ports: []int{21}, Services: []string{"ftp"}}, ssh, false},
	}
	for _, c := range cases {
		if got := Applies(c.info, c.svc); got != c.want {
			t.Errorf("%s: Applies = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTargetAddress(t *testing.T) {
	if got := (Target{Host: "10.0.0.1", Service: model.Service{Port: 80}}).Address(); got != "10.0.0.1:80" {
		t.Errorf("IPv4: %q", got)
	}
	if got := (Target{Host: "fd00::1", Service: model.Service{Port: 443}}).Address(); got != "[fd00::1]:443" {
		t.Errorf("IPv6: %q", got)
	}
	if got := (Target{Host: "example.com", Service: model.Service{Port: 21}}).Address(); got != "example.com:21" {
		t.Errorf("hostname: %q", got)
	}
}

func TestValidateOK(t *testing.T) {
	if err := Validate([]Check{good("a"), good("b-c"), good("x1-y2-z3")}); err != nil {
		t.Errorf("valid checks rejected: %v", err)
	}
	if err := Validate(nil); err != nil {
		t.Errorf("empty list is fine: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	mod := func(f func(*Info)) Check {
		c := good("ok")
		f(&c.info)
		return c
	}
	cases := []struct {
		want string // part of the expected error
		list []Check
	}{
		{"lowercase words", []Check{mod(func(i *Info) { i.ID = "Bad_ID" })}},
		{"lowercase words", []Check{mod(func(i *Info) { i.ID = "" })}},
		{"lowercase words", []Check{mod(func(i *Info) { i.ID = "-a" })}},
		{"duplicate ID", []Check{good("same"), good("same")}},
		{"missing title", []Check{mod(func(i *Info) { i.Title = " " })}},
		{"missing description", []Check{mod(func(i *Info) { i.Description = " " })}},
		{"missing fix", []Check{mod(func(i *Info) { i.Fix = "" })}},
		{"invalid severity", []Check{mod(func(i *Info) { i.Severity = 9 })}},
		{"invalid port", []Check{mod(func(i *Info) { i.Ports = []int{0} })}},
		{"invalid port", []Check{mod(func(i *Info) { i.Ports = []int{65536} })}},
		{"must be lowercase", []Check{mod(func(i *Info) { i.Services = []string{"HTTP"} })}},
		{"must be lowercase", []Check{mod(func(i *Info) { i.Services = []string{""} })}},
		{"reference missing title", []Check{mod(func(i *Info) { i.References = []Reference{{URL: "https://example.com"}} })}},
		{"invalid reference URL", []Check{mod(func(i *Info) { i.References = []Reference{{Title: "bad", URL: "javascript:alert(1)"}} })}},
		{"invalid reference URL", []Check{mod(func(i *Info) { i.References = []Reference{{Title: "empty", URL: ""}} })}},
		{"nil check", []Check{nil}},
	}
	for _, c := range cases {
		err := Validate(c.list)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("expected error containing %q, got %v", c.want, err)
		}
	}
}
